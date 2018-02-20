package client

import (
	"encoding/json"
	"github.com/mitchellh/go-homedir"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Authorization = func(registry string) (string, error)

// https://docs.docker.com/engine/reference/commandline/login/
func DockerConfigAuthorization() (Authorization, error) {
	dir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, ".docker", "config.json"))
	if os.IsNotExist(err) {
		return func(registry string) (string, error) { return "", nil }, nil // noop
	}
	config := struct {
		Auths map[string]struct {
			Auth string
		}
	}{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	lookupMap := make(map[string]string)
	for key, auth := range config.Auths {
		authTarget := strings.ToLower(key)
		if !strings.HasPrefix(key, "http://") && !strings.HasPrefix(key, "https://") {
			authTarget = "https://" + authTarget
		}
		u, err := url.Parse(authTarget)
		if err != nil {
			return nil, err
		}
		if auth.Auth != "" {
			lookupMap[u.Host] = auth.Auth
		}
	}
	return func(registry string) (string, error) {
		if registry == "registry.hub.docker.com" {
			registry = "index.docker.io"
		}
		// todo: github.com/docker/docker-credential-helpers/client
		if auth, ok := lookupMap[registry]; ok {
			return "Basic " + auth, nil
		}
		return "", nil // authorization is optional
	}, nil
}
