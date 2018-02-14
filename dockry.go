package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/dustin/go-humanize"
	"github.com/go-errors/errors"
	"github.com/mitchellh/go-homedir"
	"github.com/shyiko/dockry/cli"
	"github.com/shyiko/dockry/rfc7235"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"
)

var version string

func init() {
	log.SetFormatter(&simpleFormatter{})
	log.SetLevel(log.InfoLevel)
}

type simpleFormatter struct{}

func (f *simpleFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%s ", entry.Message)
	for k, v := range entry.Data {
		fmt.Fprintf(b, "%s=%+v ", k, v)
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

type imageRef struct {
	Registry         string
	Name             string
	Tag              string // empty if imageRef is derived from a digest
	Digest           string
	originalRegistry string
	originalName     string
}

func (m *imageRef) FQName() string {
	var s bytes.Buffer
	if m.originalRegistry != "" {
		s.WriteString(m.originalRegistry)
		s.WriteString("/")
	}
	s.WriteString(m.originalName)
	return s.String()
}

func (m *imageRef) Reference() string {
	if m.Digest != "" {
		return m.Digest
	}
	return m.Tag
}

func parseImageRef(val string) (imageRef, error) {
	var img imageRef
	split := strings.Split(val, "/")
	switch len(split) {
	case 3:
		// repo/user/node:tag
		img.originalRegistry = split[0]
		img.originalName = split[1] + "/"
		break
	case 2:
		// user/node:tag -> hub.docker.com/user/node:tag
		split = append([]string{"index.docker.io"}, split...)
		img.originalName = split[1] + "/"
	case 1:
		// node -> hub.docker.com/library/node:latest
		// node:tag -> hub.docker.com/library/node:tag
		split = append([]string{"index.docker.io", "library"}, split...)
	default:
		return img, fmt.Errorf(`"%s" is not a valid image image[:tag|@digest] reference`, val)
	}
	img.Registry = split[0]
	user, repo := split[1], split[2]
	refSplit := strings.SplitN(repo, "@", 2)
	if len(refSplit) == 1 {
		// node:6.9.1
		refSplit = append(strings.SplitN(repo, ":", 2), "latest")
		img.Tag = refSplit[1]
	} else {
		// node@sha256:cf454b60ee452473f963f60ff18ba75b8e900174aae9bf0e8051e5a83db85b30
		img.Digest = refSplit[1]
		refSplit[0] = strings.SplitN(refSplit[0], ":", 2)[0] // drop tag in case of <image>:<tag>@<digest>6
	}
	if refSplit[0] == "" {
		return img, fmt.Errorf(`"%s" is missing image name`, val)
	}
	img.Name = user + "/" + refSplit[0]
	img.originalName += refSplit[0]
	return img, nil
}

type Dockry struct {
	cache     *sync.Map
	Authorize func(registry string) (string, error)
}

// NOTE: _catalogs require different scope
type cacheKey string

func imageAccessTokenCacheKey(img imageRef) cacheKey {
	return cacheKey("access_token:" + img.FQName())
}

func (c *Dockry) request(method string, url string, headers map[string][]string, accessTokenKey cacheKey) (*http.Response, error) {
	req, err := newRequest(method, url, headers)
	accessToken, ok := c.cache.Load(accessTokenKey)
	if ok {
		req.Header.Set("Authorization", "Bearer "+accessToken.(string))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	log.Debugf("%s %s returned %d", method, url, res.StatusCode)
	if res.StatusCode == 401 {
		defer res.Body.Close()
		authorization, err := c.Authorize(req.Host)
		if err != nil {
			return nil, err
		}
		accessToken, err = acquireAccessToken(res.Header.Get("WWW-Authenticate"), authorization)
		if err != nil {
			return nil, err
		}
		c.cache.Store(accessTokenKey, accessToken)
		log.Debugf("Set %s to %s", accessTokenKey, accessToken)
		reqWithAuthz, err := newRequest(method, url, headers)
		reqWithAuthz.Header.Set("Authorization", "Bearer "+accessToken.(string))
		res, err = http.DefaultClient.Do(reqWithAuthz)
	}
	return res, err
}

func newRequest(method string, url string, headers map[string][]string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		for _, v := range value {
			req.Header.Add(key, v)
		}
	}
	return req, nil
}

func acquireAccessToken(wwwAuthenticate string, authorization string) (string, error) {
	challengeMap, err := rfc7235.ParseWWWAuthenticateToMap(wwwAuthenticate)
	if err != nil {
		return "", err
	}
	challenge, ok := challengeMap["bearer"]
	if !ok {
		return "", errors.New("Expected WWW-Authenticate carry Bearer challenge, instead got nothing")
	}
	log.Debugf("%#v", challenge)
	authURL, err := url.Parse(challenge.Params["realm"])
	if err != nil {
		return "", err
	}
	q := authURL.Query()
	for param, paramValue := range challenge.Params {
		if param != "realm" && param != "error" {
			q.Set(param, paramValue)
		}
	}
	authURL.RawQuery = q.Encode()
	method := "GET"
	encodedAuthURL := authURL.String()
	log.Debugf("Attempting to acquire token via %s %s", method, encodedAuthURL)
	req, err := http.NewRequest(method, encodedAuthURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authorization)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("%s %s resulted in %d", method, encodedAuthURL, res.StatusCode)
	}
	r := struct {
		Token string `json:"token"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("failed to deserialize response of %s %s (%s)", method, encodedAuthURL, err.Error())
	}
	return r.Token, nil
}

func (c *Dockry) Ls(image string, limit int) (string, []string, error) {
	img, err := parseImageRef(image)
	log.Debugf("%#v", img)
	if err != nil {
		return "", nil, err
	}
	method := "GET"
	query := ""
	if limit > 0 {
		query = fmt.Sprintf("?n=%d", limit)
	}
	tagsListURL := fmt.Sprintf("https://%s/v2/%s/tags/list"+query, img.Registry, img.Name)
	res, err := c.request(method, tagsListURL, nil, imageAccessTokenCacheKey(img))
	if err != nil {
		return "", nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", nil, fmt.Errorf("%s %s resulted in %d", method, tagsListURL, res.StatusCode)
	}
	r := struct {
		Tags []string `json:"tags"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return "", nil, fmt.Errorf("failed to deserialize response of %s %s (%s)", method, tagsListURL, err.Error())
	}
	reverseInPlace(r.Tags)
	rslice := r.Tags // ?n=<number> is not universally supported
	if limit > 0 && limit < len(rslice) {
		rslice = rslice[0:limit]
	}
	return img.FQName(), rslice, nil
}

func reverseInPlace(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

type Image struct {
	Name         string      `json:"name"` // e.g. registry/group/repo
	Tag          string      `json:"tag,omitempty"`
	Digest       string      `json:"digest"`       // manifest_header(Docker-Content-Digest)
	DownloadSize int         `json:"downloadSize"` // manifest.config.size + sum(manifest.layers.size)
	Os           string      `json:"os"`           // configBlob.os
	Arch         string      `json:"arch"`         // configBlob.architecture
	Timestamp    string      `json:"timestamp"`    // configBlob.created
	Config       ImageConfig `json:"config"`
}

type ImageConfig struct {
	// fields must be named after corresponding Dockerfile entries
	Cmd        []string          `json:"cmd,omitempty"`        // configBlob.config.Cmd
	Entrypoint string            `json:"entrypoint,omitempty"` // configBlob.config.Entrypoint
	Env        map[string]string `json:"env,omitempty"`        // configBlob.config.Env
	Expose     []string          `json:"expose,omitempty"`     // keys(configBlob.config.ExposedPorts)
	Label      map[string]string `json:"label,omitempty"`      // configBlob.config.Labels
	OnBuild    []string          `json:"onbuild,omitempty"`    // configBlob.config.OnBuild
	Shell      []string          `json:"shell,omitempty"`      // configBlob.config.Shell
	User       string            `json:"user,omitempty"`       // configBlob.config.User
	Volume     []string          `json:"volume,omitempty"`     // keys(configBlob.config.Volumes)
	Workdir    string            `json:"workdir,omitempty"`    // configBlob.config.WorkingDir
}

func (c *Dockry) Inspect(image string) (*Image, error) {
	img, err := parseImageRef(image)
	log.Debugf("%#v", img)
	if err != nil {
		return nil, err
	}
	method := "GET"
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", img.Registry, img.Name, img.Reference())
	res, err := c.request(method, manifestURL, map[string][]string{
		"Accept": {"application/vnd.docker.distribution.manifest.v2+json"},
	}, imageAccessTokenCacheKey(img))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s %s resulted in %d", method, manifestURL, res.StatusCode)
	}
	if res.Header.Get("Content-Type") == "application/vnd.docker.distribution.manifest.list.v2+json" {
		return nil, fmt.Errorf("%s %s is pointing to a manifest list (something that is not supported at the moment)\n"+
			"(please created a ticket at https://github.com/shyiko/dockry/issues if you need this)",
			method, manifestURL)
	}
	manifest := struct {
		Config struct {
			MediaType string
			Size      int
			Digest    string
		}
		Layers []struct {
			Size int
		}
	}{}
	if err := json.NewDecoder(res.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to deserialize response of %s %s (%s)", method, manifestURL, err.Error())
	}
	configBlob := struct {
		Os           string
		Architecture string
		Created      string
		Config       struct {
			Cmd          []string
			Entrypoint   string
			Env          []string
			ExposedPorts map[string]interface{}
			Labels       map[string]string
			OnBuild      []string
			Shell        []string
			User         string
			Volumes      map[string]interface{}
			WorkingDir   string
		}
	}{}
	if manifest.Config.MediaType == "application/vnd.docker.container.image.v1+json" {
		err := c.fetchBlob(img, manifest.Config.Digest, manifest.Config.MediaType, &configBlob)
		if err != nil {
			return nil, err
		}
	} else {
		log.Debugf("Unexpected manifest.config.mediaType \"%s\"", manifest.Config.MediaType)
	}
	var layersSize int
	for _, layer := range manifest.Layers {
		layersSize += layer.Size
	}
	env := make(map[string]string)
	for _, entry := range configBlob.Config.Env {
		split := append(strings.SplitN(entry, "=", 2), "")
		env[split[0]] = split[1]
	}
	m := &Image{
		Name:   img.FQName(),
		Tag:    img.Tag,
		Digest: res.Header.Get("Docker-Content-Digest"),
		// manifest.Config.Size is not included so that value would match
		// https://hub.docker.com/v2/repositories/%s/tags/
		DownloadSize:/*manifest.Config.Size + */ layersSize,
		Os:        configBlob.Os,
		Arch:      configBlob.Architecture,
		Timestamp: configBlob.Created,
		Config: ImageConfig{
			Cmd:        configBlob.Config.Cmd,
			Entrypoint: configBlob.Config.Entrypoint,
			Env:        env,
			Expose:     keys(configBlob.Config.ExposedPorts),
			Label:      configBlob.Config.Labels,
			OnBuild:    configBlob.Config.OnBuild,
			Shell:      configBlob.Config.Shell,
			User:       configBlob.Config.User,
			Volume:     keys(configBlob.Config.Volumes),
			Workdir:    configBlob.Config.WorkingDir,
		},
	}
	return m, nil
}

func keys(m map[string]interface{}) []string {
	var r []string
	for key := range m {
		r = append(r, key)
	}
	return r
}

func (c *Dockry) fetchBlob(img imageRef, digest string, mediaType string, v interface{}) error {
	method := "GET"
	manifestURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", img.Registry, img.Name, digest)
	res, err := c.request(method, manifestURL, map[string][]string{
		"Accept": {mediaType},
	}, imageAccessTokenCacheKey(img))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s %s resulted in %d", method, manifestURL, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return fmt.Errorf("failed to deserialize response of %s %s (%s)", method, manifestURL, err.Error())
	}
	return nil
}

func (c *Dockry) Rm(image string) (bool, error) {
	img, err := parseImageRef(image)
	log.Debugf("%#v", img)
	if err != nil {
		return false, err
	}
	// todo:
	// Docker Hub does not support DELETE at the moment
	// we might want to
	// if img.Registry == "index.docker.io" {
	// DELETE https://hub.docker.com/v2/repositories/%s/tags/%s
	// e.g. https://hub.docker.com/v2/repositories/shyiko/openvpn/tags/2.4.0_easyrsa-3.0.3
	// } else below
	// (might not be a good idea considering @digest expectation below)
	if img.Digest == "" {
		return false, fmt.Errorf("%s@<digest> is needed", img.FQName())
	}
	method := "DELETE"
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", img.Registry, img.Name, img.Digest)
	res, err := c.request(method, manifestURL, map[string][]string{
		"Accept": {"application/vnd.docker.distribution.manifest.v2+json"},
	}, imageAccessTokenCacheKey(img))
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode > 400 && res.StatusCode != 404 {
		return false, fmt.Errorf("%s %s resulted in %d", method, manifestURL, res.StatusCode)
	}
	return res.StatusCode == 202, nil
}

func NewDockry() (*Dockry, error) {
	return &Dockry{
		cache:     &sync.Map{},
		Authorize: readAuthorizationForTokenEndpoint,
	}, nil
}

func readAuthorizationForTokenEndpoint(registry string) (string, error) {
	// https://docs.docker.com/engine/reference/commandline/login/
	// todo: github.com/docker/docker-credential-helpers/client
	dir, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, ".docker", "config.json"))
	if os.IsNotExist(err) {
		return "", nil
	}
	config := struct {
		Auths map[string]struct {
			Auth string
		}
	}{}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", err
	}
	for key, auth := range config.Auths {
		authTarget := strings.ToLower(key)
		if !strings.HasPrefix(key, "http://") && !strings.HasPrefix(key, "https://") {
			authTarget = "https://" + authTarget
		}
		u, err := url.Parse(authTarget)
		if err != nil {
			return "", err
		}
		// todo: index.docker.io == registry.hub.docker.com
		if u.Host == registry && auth.Auth != "" {
			log.Debugf("Found %s auth in ~/.docker/config.json", key)
			return "Basic " + auth.Auth, nil
		}
	}
	return "", nil // surprisingly, authorization is optional
}

func main() {
	completion := cli.NewCompletion()
	completed, err := completion.Execute()
	if err != nil {
		log.Debug(err)
		os.Exit(3)
	}
	if completed {
		os.Exit(0)
	}
	var user string
	var limit int
	var fq bool
	newDockry := func() *Dockry {
		d, err := NewDockry()
		if err != nil {
			log.Fatal(err)
		}
		d.Authorize = func(registry string) (string, error) {
			if user == "" {
				return readAuthorizationForTokenEndpoint(registry)
			}
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user)), nil
		}
		return d
	}
	rootCmd := &cobra.Command{
		Use:  "dockry",
		Long: "Docker Registry client (https://github.com/shyiko/dockry).",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug, _ := cmd.Flags().GetBool("debug"); debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
				fmt.Println(version)
				return nil
			}
			return pflag.ErrHelp
		},
	}
	lsCommand := &cobra.Command{
		Use:   "ls [image]",
		Short: "List image tags",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			dockry := newDockry()
			name, tags, err := dockry.Ls(args[0], limit)
			if err != nil {
				log.Fatal(err)
			}
			for _, tag := range tags {
				prefix := ""
				if fq {
					prefix = name + ":"
				}
				fmt.Println(prefix + tag)
			}
			return nil
		},
		Example: "  dockry ls --fq node",
	}
	lsCommand.Flags().IntVar(&limit, "limit", 0, "Maximum number of records to show")
	lsCommand.Flags().BoolVar(&fq, "fq", false, "Output tag(s) fully-qualified")
	rootCmd.AddCommand(lsCommand)
	llCommand := &cobra.Command{
		Use:   "ll [image]",
		Short: `List image "<tag> <download size> <time since update>"s`,
		Long: `List image "<tag> <download size> <time since update>"s` +
			"\nAn alias for `inspect $(dockry ls <image> <flags>) --format=$'{{.tag}}\\t{{.downloadSize | hsize}}\\t{{.timestamp | htime}}'`",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			dockry := newDockry()
			name, tags, err := dockry.Ls(args[0], limit)
			if err != nil {
				log.Fatal(err)
			}
			for _, tag := range tags {
				image, err := dockry.Inspect(name + ":" + tag)
				if err != nil {
					log.Fatal(err)
				}
				prefix := ""
				if fq {
					prefix = "{{.name}}:"
				}
				printlnf(prefix+"{{.tag}}\t{{.downloadSize | hsize}}\t{{.timestamp | htime}}", image)
			}
			return nil
		},
		Example: "  dockry ll --fq node",
	}
	llCommand.Flags().IntVar(&limit, "limit", 0, "Maximum number of records to show")
	llCommand.Flags().BoolVar(&fq, "fq", false, "Output tag(s) fully-qualified")
	rootCmd.AddCommand(llCommand)
	inspectCommand := &cobra.Command{
		Use:     "inspect [image:tag or image@digest]",
		Aliases: []string{"i"},
		Short:   "Display detailed information on one or more images",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			dockry := newDockry()
			for _, imageRef := range args {
				image, err := dockry.Inspect(imageRef)
				if err != nil {
					log.Fatal(err)
				}
				format, err := cmd.Flags().GetString("format")
				if err != nil {
					return err
				}
				printlnf(format, image)
			}
			return nil
		},
		Example: "  dockry inspect node:latest",
	}
	inspectCommand.Flags().String("format", "", "Go template to render (applied separately to each record)\n"+
		"    Additional functions:\n"+
		"      def - e.g. {{- if def .config.env VAR }} ... {{- end }} - render content between }} and {{ only if .config.env.VAR is set\n"+
		"      hsize - e.g. {{ .downloadSize | hsize }} - humanize size (e.g. 1 MB)\n"+
		"      htime - e.g. {{ .timestamp | htime }} - humanize time (e.g. 1 month ago)"+
		"")
	rootCmd.AddCommand(inspectCommand)
	digestCommand := &cobra.Command{
		Use:     "digest [image:tag...]",
		Aliases: []string{"d"},
		Short:   "Print digest(s) of one or more images",
		Long: "Print digest(s) of one or more images" +
			"\nAn alias for `inspect <image>:<tag>... <flags> --format='{{.digest}}'`",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			dockry := newDockry()
			for _, imageRef := range args {
				image, err := dockry.Inspect(imageRef)
				if err != nil {
					log.Fatal(err)
				}
				prefix := ""
				if fq {
					prefix = image.Name + "@"
				}
				fmt.Println(prefix + image.Digest)
			}
			return nil
		},
		Example: "  dockry digest --fq node:latest",
	}
	digestCommand.Flags().BoolVar(&fq, "fq", false, "Output digest(s) fully-qualified")
	rootCmd.AddCommand(digestCommand)
	rmCommand := &cobra.Command{
		Use:   "rm [image@digest...]",
		Short: "Remove one or more images",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			dockry := newDockry()
			for _, imageRef := range args {
				ok, err := dockry.Rm(imageRef)
				if err != nil {
					log.Fatal(err)
				}
				if ok {
					fmt.Println(imageRef + " removed")
				}
			}
			return nil
		},
		Example: "  dockry rm node@sha256:5ff43da...",
	}
	rootCmd.AddCommand(rmCommand)
	completionCmd := &cobra.Command{
		Use:   "completion",
		Short: "Command-line completion",
	}
	completionCmd.AddCommand(
		&cobra.Command{
			Use:   "bash",
			Short: "Generate Bash completion",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return pflag.ErrHelp
				}
				if err := completion.GenBashCompletion(os.Stdout); err != nil {
					log.Error(err)
				}
				return nil
			},
			Example: "  source <(dockry completion bash)",
		},
		&cobra.Command{
			Use:   "zsh",
			Short: "Generate Z shell completion",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return pflag.ErrHelp
				}
				if err := completion.GenZshCompletion(os.Stdout); err != nil {
					log.Error(err)
				}
				return nil
			},
			Example: "  source <(dockry completion zsh)",
		},
	)
	rootCmd.AddCommand(completionCmd)
	rootCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "Explicit username:password for authorization"+
		" (by default ~/.docker/config.json is used)")
	walk(rootCmd, func(cmd *cobra.Command) {
		cmd.Flags().BoolP("help", "h", false, "Print usage")
		cmd.Flags().MarkHidden("help")
	})
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug output")
	rootCmd.Flags().Bool("version", false, "Print version information")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func walk(cmd *cobra.Command, cb func(*cobra.Command)) {
	cb(cmd)
	for _, c := range cmd.Commands() {
		walk(c, cb)
	}
}

func newTemplate(tmpl string) (*template.Template, error) {
	humanizeSize := func(v interface{}) (interface{}, error) {
		if n, ok := v.(json.Number); ok {
			nn, err := n.Int64()
			if err != nil {
				return nil, err
			}
			return humanize.Bytes(uint64(nn)), nil
		}
		return v, nil
	}
	humanizeTime := func(v interface{}) (interface{}, error) {
		if s, ok := v.(string); ok && s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return nil, err
			}
			return humanize.Time(t), nil
		}
		return v, nil
	}
	funcMap := template.FuncMap{
		"def": func(m map[string]interface{}, key string) (interface{}, error) {
			_, ok := m[key]
			return ok, nil
		},
		"hsize": humanizeSize,
		"htime": humanizeTime,
	}
	return template.New("template").Funcs(funcMap).Option("missingkey=error").Parse(tmpl)
}

func printlnf(format string, images ...*Image) {
	b, err := json.MarshalIndent(images, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if format != "" {
		var input []map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber() // so that DownloadSize would not turn into float64
		if err := decoder.Decode(&input); err != nil {
			log.Fatal(err)
		}
		t, err := newTemplate(format)
		if err != nil {
			log.Fatal(err)
		}
		for _, record := range input {
			buf := &bytes.Buffer{}
			if err := t.Execute(buf, record); err != nil {
				log.Fatal(err)
			}
			output(buf.Bytes())
		}
		return
	}
	output(b)
}

func output(b []byte) {
	os.Stdout.Write(b)
	fmt.Println()
}
