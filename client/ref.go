package client

import (
	"bytes"
	"fmt"
	"strings"
)

type ImageRef struct {
	Registry    string
	RegistryRaw string
	Name        string
	NameRaw     string
	Tag         string // empty if ImageRef is derived from a digest
	TagRaw      string
	Digest      string
}

func (m *ImageRef) FQNameRaw() string {
	var s bytes.Buffer
	if m.RegistryRaw != "" {
		s.WriteString(m.RegistryRaw)
		s.WriteString("/")
	}
	s.WriteString(m.NameRaw)
	return s.String()
}

func (m *ImageRef) Reference() string {
	if m.Digest != "" {
		return m.Digest
	}
	return m.Tag
}

func ParseImageRef(val string) (ImageRef, error) {
	var img ImageRef
	split := strings.Split(val, "/")
	switch len(split) {
	case 3:
		// repo/user/node:tag
		img.RegistryRaw = split[0]
		img.NameRaw = split[1] + "/"
		break
	case 2:
		// user/node:tag -> hub.docker.com/user/node:tag
		split = append([]string{"index.docker.io"}, split...)
		img.NameRaw = split[1] + "/"
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
		refSplit = strings.SplitN(repo, ":", 2)
		if len(refSplit) == 2 {
			img.TagRaw = refSplit[1]
		} else {
			refSplit = append(refSplit, "latest")
		}
		img.Tag = refSplit[1]
	} else {
		// node@sha256:cf454b60ee452473f963f60ff18ba75b8e900174aae9bf0e8051e5a83db85b30
		img.Digest = refSplit[1]
		refSplit[0] = strings.SplitN(refSplit[0], ":", 2)[0] // drop tag in case of <image>:<tag>@<digest>
	}
	if refSplit[0] == "" {
		return img, fmt.Errorf(`"%s" is missing image name`, val)
	}
	img.Name = user + "/" + refSplit[0]
	img.NameRaw += refSplit[0]
	return img, nil
}

func MustParseImageRef(val string) ImageRef {
	img, err := ParseImageRef(val)
	if err != nil {
		panic(err)
	}
	return img
}
