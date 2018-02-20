package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/dustin/go-humanize"
	"github.com/go-errors/errors"
	"github.com/shyiko/dockry/client"
	"github.com/shyiko/dockry/client/registry/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"math"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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

func main() {
	completion := NewCompletion()
	completed, err := completion.Execute()
	if err != nil {
		log.Debug(err)
		os.Exit(3)
	}
	if completed {
		os.Exit(0)
	}
	var fq bool
	var limit int
	var user string
	newV2Client := func() *v2.Client {
		c, err := v2.NewClient()
		if err != nil {
			log.Fatal(err)
		}
		if user != "" {
			c.Authorization = func(registry string) (string, error) {
				return "Basic " + base64.StdEncoding.EncodeToString([]byte(user)), nil
			}
		}
		return c
	}
	newPlatformFilter := func(cmd *cobra.Command) (*v2.PlatformFilter, string, error) {
		p, err := cmd.Flags().GetString("platform")
		if err != nil {
			return nil, "", err
		}
		l64, err := cmd.Flags().GetBool("l64")
		if err != nil {
			return nil, "", err
		}
		if l64 {
			if p != "" {
				return nil, "", errors.New("--platform/-p and --l64/-x cannot be used together")
			}
			p = "linux/amd64"
		}
		platform, err := parsePlatform(p)
		if err != nil {
			return nil, "", fmt.Errorf("--platform: %s", err.Error())
		}
		strict, err := cmd.Flags().GetBool("strict")
		if err != nil {
			return nil, "", err
		}
		pf := &v2.PlatformFilter{Platform: platform, Strict: strict}
		log.Debugf("%#v", *pf)
		log.Debugf("%#v", *pf.Platform)
		return pf, p, nil
	}
	rootCmd := &cobra.Command{
		Use:  "dockry",
		Long: "Docker Registry client (https://github.com/shyiko/dockry).",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug, _ := cmd.Flags().GetBool("debug"); debug {
				log.SetLevel(log.DebugLevel)
			}
			if limit < 0 {
				limit = math.MaxInt32
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
			if len(args) != 1 {
				return pflag.ErrHelp
			}
			c := newV2Client()
			tags, err := c.LsWithOpt(args[0], v2.LsOpt{Limit: limit})
			if err != nil {
				log.Fatal(err)
			}
			img := client.MustParseImageRef(args[0])
			name := img.FQNameRaw()
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
			"\nAn alias for `inspect $(dockry ls <image> <flags>) --format=$'{{.tag}}\\t{{.downloadSize | na | hsize}}\\t{{.timestamp | hsince}}'`",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return pflag.ErrHelp
			}
			pf, p, err := newPlatformFilter(cmd)
			if err != nil {
				return err
			}
			c := newV2Client()
			lsOpt := v2.LsOpt{Limit: limit}
			if p != "" {
				lsOpt.Limit = 0
			}
			tags, err := c.LsWithOpt(args[0], lsOpt)
			if err != nil {
				log.Fatal(err)
			}
			img := client.MustParseImageRef(args[0])
			name := img.FQNameRaw()
			prefix := ""
			if fq {
				prefix = `.name ":"`
			}
			maxTagLen := 0
			for _, tag := range tags {
				l := len(tag)
				if maxTagLen < l {
					maxTagLen = l
				}
			}
			padding := maxTagLen + len(" (windows,10.0.14393.2068/arm64,v8(sse))")
			if fq {
				padding += len(name) + 1
			}
			format := `{{with $ref := (print ` + prefix + ` .tag " (" (. | platform) ")")}}{{pad $ref ` + strconv.Itoa(padding) + `}}{{end}}` +
				"\t{{.downloadSize | na | hsize}}\t{{.timestamp | hsince}}"
			out := newOutputStream(format)
			l := limit
			for _, tag := range tags {
				if l < 1 {
					break
				}
				ch, errch := c.InspectCWithOpt(name+":"+tag, v2.InspectOpt{PlatformFilter: pf, Limit: l})
				for img := range ch {
					out.write(img)
					l--
				}
				if err := <-errch; err != nil {
					log.Fatal(err)
				}
			}
			out.flush()
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
			pf, _, err := newPlatformFilter(cmd)
			if err != nil {
				return err
			}
			format, err := cmd.Flags().GetString("format")
			if err != nil {
				return err
			}
			c := newV2Client()
			out := newOutputStream(format)
			l := limit
			for _, imageRef := range args {
				if l < 1 {
					break
				}
				ch, errch := c.InspectCWithOpt(imageRef, v2.InspectOpt{PlatformFilter: pf, Limit: l})
				for img := range ch {
					out.write(img)
					l--
				}
				if err := <-errch; err != nil {
					log.Fatal(err)
				}
			}
			out.flush()
			return nil
		},
		Example: "  dockry inspect node:latest",
	}
	inspectCommand.Flags().String("format", "", "Go template to render (applied separately to each record)\n"+
		"    Additional functions:\n"+
		"      def - e.g. {{- if def .config.env VAR }} ... {{- end }} - render content between }} and {{ only if .config.env.VAR is set\n"+
		"      hsize - e.g. {{ .downloadSize | hsize }} - humanize size (e.g. 1 MB)\n"+
		"      na - e.g. {{ .downloadSize | na }} - show n/a if 0\n"+
		"      hsince - e.g. {{ .timestamp | hsince }} - humanize time (e.g. 1 month ago)\n"+
		"      platform - e.g. {{ . | platform }} - combine os/cpu-related info into a single value (e.g. linux/amd64)\n"+
		"      pad - e.g. {{ pad .tag 50 }} - append padding if necessary"+
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
			pf, _, err := newPlatformFilter(cmd)
			if err != nil {
				return err
			}
			c := newV2Client()
			l := limit
			for _, imageRef := range args {
				if l < 1 {
					break
				}
				ch, errch := c.InspectCWithOpt(imageRef, v2.InspectOpt{PlatformFilter: pf, Limit: l})
				for img := range ch {
					prefix := ""
					if fq {
						prefix = img.Name + "@"
					}
					fmt.Println(prefix + img.Digest)
					l--
				}
				if err := <-errch; err != nil {
					log.Fatal(err)
				}
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
			c := newV2Client()
			for _, imageRef := range args {
				ok, err := c.Rm(imageRef)
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
	for _, cmd := range []*cobra.Command{
		inspectCommand,
		llCommand,
		digestCommand,
	} {
		cmd.Flags().StringP("platform", "p", "", `Filter images by platform (e.g. "current", "linux/amd64")`)
		cmd.Flags().BoolP("l64", "x", false, "An alias for --platform=linux/amd64")
		cmd.Flags().Bool("strict", false,
			"Match --platform exactly (e.g. '-p linux/arm' matches \"linux/arm,v6\" and \"linux/arm,v7\", while '-p linux/arm --strict' only \"linux/arm\")")
	}
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

var platformRegex0 = `(?:(\w+)(?:,([^/(]+))?(?:\((\w+(?:,\w+)*)\))?)?`
var platformRegex = regexp.MustCompile("^" + platformRegex0 + "/?" + platformRegex0 + "$")

func parsePlatform(qs string) (*v2.Platform, error) {
	switch qs {
	case "current":
		return &v2.Platform{
			Os:   runtime.GOOS,
			Arch: runtime.GOARCH,
		}, nil
	case "":
		return &v2.Platform{}, nil
	}
	mm := platformRegex.FindAllStringSubmatch(qs, -1)
	if len(mm) != 1 {
		return nil, fmt.Errorf("%s is not a valid platform qualifier "+
			"(expected '<os>,<os version>(<os features comma-separated>)/<arch>,<cpu variant>(<cpu features comma-separated>)'"+
			", e.g. linux/arm64,v8)", qs)
	}
	m := mm[0]
	// group 1 - os
	// group 2 - os version
	// group 3 - os features (comma-separated)
	// group 4 - arch
	// group 5 - cpu variant
	// group 6 - cpu features (comma-separated)
	return &v2.Platform{
		Os:         m[1],
		OsVersion:  m[2],
		OsFeature:  splitNotEmpty(m[3], ","),
		Arch:       m[4],
		CpuVariant: m[5],
		CpuFeature: splitNotEmpty(m[6], ","),
	}, nil
}

func splitNotEmpty(s string, d string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, d)
}

func newTemplate(tmpl string) (*template.Template, error) {
	funcMap := template.FuncMap{
		"def": func(m map[string]interface{}, key string) (interface{}, error) {
			_, ok := m[key]
			return ok, nil
		},
		"hsize": func(v interface{}) (interface{}, error) {
			if n, ok := v.(json.Number); ok {
				nn, err := n.Int64()
				if err != nil {
					return nil, err
				}
				return humanize.Bytes(uint64(nn)), nil
			}
			return v, nil
		},
		"hsince": func(v interface{}) (interface{}, error) {
			if s, ok := v.(string); ok && s != "" {
				t, err := time.Parse(time.RFC3339Nano, s)
				if err != nil {
					return nil, err
				}
				return humanize.Time(t), nil
			}
			return v, nil
		},
		"na": func(v interface{}) (interface{}, error) {
			if n, ok := v.(json.Number); ok {
				nn, err := n.Int64()
				if err != nil {
					return nil, err
				}
				if nn == 0 {
					return "n/a", nil
				}
			}
			return v, nil
		},
		"platform": func(m map[string]interface{}) (interface{}, error) {
			buf := &bytes.Buffer{}
			buf.WriteString(m["os"].(string))
			if m["osVersion"] != nil {
				buf.WriteString("," + m["osVersion"].(string))
				if m["osFeature"] != nil {
					buf.WriteString("(" + strings.Join(m["osFeature"].([]string), ",") + ")")
				}
			}
			buf.WriteString("/" + m["arch"].(string))
			if m["cpuVariant"] != nil {
				buf.WriteString("," + m["cpuVariant"].(string))
				if m["cpuFeature"] != nil {
					buf.WriteString("(" + strings.Join(m["cpuFeature"].([]string), ",") + ")")
				}
			}
			return buf.String(), nil
		},
		"pad": func(v interface{}, def int) (interface{}, error) {
			if s, ok := v.(string); ok && s != "" {
				d := def
				l := len(s)
				if d < l {
					d = l
				}
				return s + strings.Repeat(" ", d-l), nil
			}
			return v, nil
		},
	}
	return template.New("template").Funcs(funcMap).Option("missingkey=error").Parse(tmpl)
}

type outputStream struct {
	tpl    *template.Template
	images []*v2.Image
}

func (s *outputStream) write(images ...*v2.Image) {
	if s.tpl != nil {
		b, err := json.MarshalIndent(images, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		var input []map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber() // so that DownloadSize would not turn into float64
		if err := decoder.Decode(&input); err != nil {
			log.Fatal(err)
		}
		for _, record := range input {
			buf := &bytes.Buffer{}
			if err := s.tpl.Execute(buf, record); err != nil {
				log.Fatal(err)
			}
			printbln(buf.Bytes())
		}
	} else {
		s.images = append(s.images, images...)
	}
}

func (s *outputStream) flush() {
	if s.tpl == nil {
		if s.images == nil {
			s.images = []*v2.Image{} // so that result would be empty array instead of null
		}
		b, err := json.MarshalIndent(s.images, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		printbln(b)
	}
}

func newOutputStream(format string) outputStream {
	var tpl *template.Template
	if format != "" {
		var err error
		tpl, err = newTemplate(string(format))
		if err != nil {
			log.Fatal(err)
		}
	}
	return outputStream{tpl, nil}
}

func printbln(b []byte) {
	os.Stdout.Write(b)
	fmt.Println()
}
