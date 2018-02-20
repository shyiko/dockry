package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/shyiko/dockry/client"
	"github.com/shyiko/dockry/rfc7235"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type Client struct {
	Authorization func(registry string) (string, error)
	cache         *sync.Map
}

type cacheKey string

func imageAccessTokenCacheKey(img client.ImageRef) cacheKey {
	return cacheKey("access_token:" + img.FQNameRaw())
}

func (c *Client) request(method string, url string, headers map[string][]string, tokenCacheKey cacheKey) (*http.Response, error) {
	req, err := newRequest(method, url, headers)
	accessToken, ok := c.cache.Load(tokenCacheKey)
	if ok {
		req.Header.Set("Authorization", "Bearer "+accessToken.(string))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	logResponseCode(req, res)
	if res.StatusCode == 401 {
		defer res.Body.Close()
		authorization, err := c.Authorization(req.Host)
		if err != nil {
			return nil, err
		}
		accessToken, err = c.exchangeAuthorizationForAccessToken(res.Header.Get("WWW-Authenticate"), authorization)
		if err != nil {
			return nil, err
		}
		c.cache.Store(tokenCacheKey, accessToken)
		log.Debugf("Set %s to %s", tokenCacheKey, accessToken)
		reqWithAuthz, err := newRequest(method, url, headers)
		reqWithAuthz.Header.Set("Authorization", "Bearer "+accessToken.(string))
		res, err = http.DefaultClient.Do(reqWithAuthz)
		logResponseCode(reqWithAuthz, res)
	}
	return res, err
}

func logResponseCode(req *http.Request, res *http.Response) {
	accept := req.Header["Accept"]
	if len(accept) == 0 {
		accept = []string{"*/*"}
	}
	log.Debugf("%s %s %s returned %d (%s)", req.Method, req.URL.String(), accept, res.StatusCode, res.Header.Get("Content-Type"))
}

type ApiError struct {
	StatusCode int
	msg        string
}

func (e *ApiError) Error() string {
	return e.msg
}

func newHTTPError(method string, url string, statusCode int) error {
	return &ApiError{
		statusCode,
		fmt.Sprintf("%s %s resulted in %d (%s)", method, url, statusCode, http.StatusText(statusCode)),
	}
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

func (c *Client) exchangeAuthorizationForAccessToken(wwwAuthenticate string, authorization string) (string, error) {
	challengeMap, err := rfc7235.ParseWWWAuthenticateToMap(wwwAuthenticate)
	if err != nil {
		return "", err
	}
	challenge, ok := challengeMap["bearer"]
	if !ok {
		return "", errors.New("Expected WWW-Authenticate carry Bearer challenge and yet it didn't")
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
		return "", newHTTPError(method, encodedAuthURL, res.StatusCode)
	}
	r := struct {
		Token string `json:"token"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, encodedAuthURL, err.Error())
	}
	return r.Token, nil
}

func (c *Client) Ls(image string, limit int) ([]string, error) {
	img, err := client.ParseImageRef(image)
	log.Debugf("%#v", img)
	if img.Digest != "" {
		return nil, errors.New("Listing tags by digest is not supported")
	}
	if err != nil {
		return nil, err
	}
	method := "GET"
	query := ""
	if limit > 0 {
		query = fmt.Sprintf("?n=%d", limit)
	}
	tagsListURL := fmt.Sprintf("https://%s/v2/%s/tags/list"+query, img.Registry, img.Name)
	res, err := c.request(method, tagsListURL, nil, imageAccessTokenCacheKey(img))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, newHTTPError(method, tagsListURL, res.StatusCode)
	}
	r := struct {
		Tags []string `json:"tags"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, tagsListURL, err.Error())
	}
	if img.TagRaw != "" {
		for _, tag := range r.Tags {
			if tag == img.TagRaw {
				return []string{tag}, nil
			}
		}
		return nil, nil
	}
	reverseInPlace(r.Tags)
	rslice := r.Tags // ?n=<number> is not universally supported
	if limit > 0 && limit < len(rslice) {
		rslice = rslice[0:limit]
	}
	return rslice, nil
}

func reverseInPlace(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

type Image struct {
	Name         string `json:"name"` // e.g. registry/group/repo
	Tag          string `json:"tag,omitempty"`
	Digest       string `json:"digest"`       // manifest_header(Docker-Content-Digest)
	DownloadSize int    `json:"downloadSize"` // manifest.config.size + sum(manifest.layers.size)
	*Platform
	Timestamp string      `json:"timestamp"` // configBlob.created
	Config    ImageConfig `json:"config"`
}

type ImageConfig struct {
	// fields must be named after corresponding Dockerfile entries
	Cmd        []string          `json:"cmd,omitempty"`        // configBlob.config.Cmd
	Entrypoint []string          `json:"entrypoint,omitempty"` // configBlob.config.Entrypoint
	Env        map[string]string `json:"env,omitempty"`        // configBlob.config.Env
	Expose     []string          `json:"expose,omitempty"`     // keys(configBlob.config.ExposedPorts)
	Label      map[string]string `json:"label,omitempty"`      // configBlob.config.Labels
	OnBuild    []string          `json:"onbuild,omitempty"`    // configBlob.config.OnBuild
	Shell      []string          `json:"shell,omitempty"`      // configBlob.config.Shell
	User       string            `json:"user,omitempty"`       // configBlob.config.User
	Volume     []string          `json:"volume,omitempty"`     // keys(configBlob.config.Volumes)
	Workdir    string            `json:"workdir,omitempty"`    // configBlob.config.WorkingDir
}

type Platform struct {
	Os         string   `json:"os"` // configBlob.os
	OsVersion  string   `json:"osVersion,omitempty"`
	OsFeature  []string `json:"osFeature,omitempty"`
	Arch       string   `json:"arch"` // configBlob.architecture
	CpuVariant string   `json:"cpuVariant,omitempty"`
	CpuFeature []string `json:"cpuFeature,omitempty"`
}

type PlatformFilter struct {
	*Platform
	Strict bool
}

func (p *PlatformFilter) accept(o *Platform) bool {
	if p == nil {
		return true
	}
	return (p.Os == "" || p.Os == o.Os) &&
		(p.Arch == "" || p.Arch == o.Arch) &&
		(p.OsVersion == "" || p.OsVersion == o.OsVersion) &&
		(p.CpuVariant == "" || p.CpuVariant == o.CpuVariant) &&
		isSliceSubset(p.OsFeature, o.OsFeature) &&
		isSliceSubset(p.CpuFeature, o.CpuFeature) &&
		(!p.Strict || isSliceSubset(o.OsFeature, p.OsFeature) && isSliceSubset(o.CpuFeature, p.CpuFeature))
}

func isSliceSubset(l, r []string) bool {
	if len(l) == 0 {
		return true
	}
	m := make(map[string]bool)
	for _, k := range r {
		m[k] = true
	}
	for _, k := range l {
		if !m[k] {
			return false
		}
	}
	return true
}

func (c *Client) Inspect(ref string, pf *PlatformFilter) ([]*Image, error) {
	ch, errch := c.InspectC(ref, pf)
	var r []*Image
	for img := range ch {
		r = append(r, img)
	}
	if err := <-errch; err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) InspectC(ref string, pf *PlatformFilter) (<-chan *Image, <-chan error) {
	ch := make(chan *Image)
	errch := make(chan error, 1)
	go func() {
		defer close(ch)
		img, err := client.ParseImageRef(ref)
		log.Debugf("%#v", img)
		if err != nil {
			errch <- err
			return
		}
		method := "GET"
		manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", img.Registry, img.Name, img.Reference())
		res, err := c.request(method, manifestURL, map[string][]string{
			"Accept": {
				"application/vnd.docker.distribution.manifest.list.v2+json",
				"application/vnd.docker.distribution.manifest.v2+json",
			},
		}, imageAccessTokenCacheKey(img))
		if err != nil {
			errch <- err
			return
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			errch <- newHTTPError(method, manifestURL, res.StatusCode)
			return
		}
		if res.Header.Get("Content-Type") == "application/vnd.docker.distribution.manifest.list.v2+json" {
			manifestList := struct {
				Manifests []struct {
					Digest   string
					Platform struct {
						Architecture string
						Os           string
						OsVersion    string   `json:"os.version"`
						OsFeatures   []string `json:"os.features"`
						Variant      string
						Features     []string
					}
				}
			}{}
			if err := json.NewDecoder(res.Body).Decode(&manifestList); err != nil {
				errch <- fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, manifestURL, err.Error())
				return
			}
			for _, manifest := range manifestList.Manifests {
				platform := &Platform{
					Os:         manifest.Platform.Os,
					OsVersion:  manifest.Platform.OsVersion,
					OsFeature:  manifest.Platform.OsFeatures,
					Arch:       manifest.Platform.Architecture,
					CpuVariant: manifest.Platform.Variant,
					CpuFeature: manifest.Platform.Features,
				}
				if !pf.accept(platform) {
					continue
				}
				ref := img.FQNameRaw() + "@" + manifest.Digest
				cch, cerrch := c.InspectC(ref, pf) // nil instead of pf for e.g. linux/arm64,v8 sake
				for imgx := range cch {
					imgx.Tag = img.Tag
					imgx.Platform = platform
					ch <- imgx
				}
				if err := <-cerrch; err != nil {
					errch <- err
					return
				}
			}
			errch <- nil
			return
		}
		configBlob := struct {
			Os           string
			Architecture string
			Created      string
			Config       struct {
				Cmd          []string
				Entrypoint   []string
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
		var layersSize int
		if strings.HasPrefix(res.Header.Get("Content-Type"), "application/vnd.docker.distribution.manifest.v1") {
			manifestV1 := struct {
				History []struct {
					V1Compatibility string
				}
			}{}
			if err := json.NewDecoder(res.Body).Decode(&manifestV1); err != nil {
				errch <- fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, manifestURL, err.Error())
				return
			}
			if len(manifestV1.History) > 0 {
				if err := json.Unmarshal([]byte(manifestV1.History[0].V1Compatibility), &configBlob); err != nil {
					errch <- fmt.Errorf("Failed to deserialize history.v1Compatibility (%s)", err.Error())
					return
				}
			}
		} else {
			m := struct {
				Config struct {
					MediaType string
					Size      int
					Digest    string
				}
				Layers []struct {
					Size int
				}
			}{}
			if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
				errch <- fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, manifestURL, err.Error())
				return
			}
			if m.Config.Digest != "" {
				err := c.fetchBlob(img, m.Config.Digest, m.Config.MediaType, &configBlob)
				if err != nil {
					errch <- err
					return
				}
			}
			for _, layer := range m.Layers {
				layersSize += layer.Size
			}
		}
		platform := &Platform{
			Os:   configBlob.Os,
			Arch: configBlob.Architecture,
		}
		if pf.accept(platform) {
			env := make(map[string]string)
			for _, entry := range configBlob.Config.Env {
				split := append(strings.SplitN(entry, "=", 2), "")
				env[split[0]] = split[1]
			}
			m := &Image{
				Name:   img.FQNameRaw(),
				Tag:    img.Tag,
				Digest: res.Header.Get("Docker-Content-Digest"),
				// manifest.Config.Size is not included so that value would match
				// https://hub.docker.com/v2/repositories/%s/tags/
				DownloadSize:/*manifest.Config.Size + */ layersSize,
				Platform:  platform,
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
			ch <- m
		}
		errch <- nil
	}()
	return ch, errch
}

func keys(m map[string]interface{}) []string {
	var r []string
	for key := range m {
		r = append(r, key)
	}
	return r
}

func (c *Client) fetchBlob(img client.ImageRef, digest string, mediaType string, v interface{}) error {
	method := "GET"
	blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", img.Registry, img.Name, digest)
	res, err := c.request(method, blobURL, map[string][]string{
		"Accept": {mediaType},
	}, imageAccessTokenCacheKey(img))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return newHTTPError(method, blobURL, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return fmt.Errorf("Failed to deserialize response of %s %s (%s)", method, blobURL, err.Error())
	}
	return nil
}

func (c *Client) Rm(ref string) (bool, error) {
	img, err := client.ParseImageRef(ref)
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
		return false, fmt.Errorf("%s@<digest> is needed", img.FQNameRaw())
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
	if res.StatusCode >= 400 && res.StatusCode != 404 {
		return false, newHTTPError(method, manifestURL, res.StatusCode)
	}
	return res.StatusCode == 202, nil
}

func NewClient() (*Client, error) {
	authorization, err := client.DockerConfigAuthorization()
	if err != nil {
		return nil, err
	}
	return &Client{
		Authorization: authorization,
		cache:         &sync.Map{},
	}, nil
}
