# dockry ![Latest Version](https://img.shields.io/badge/latest-0.1.0-blue.svg) [![Build Status](https://travis-ci.org/shyiko/dockry.svg?branch=master)](https://travis-ci.org/shyiko/dockry)

Docker Registry V2 command-line client  
(compatible with any registry implementing [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/), ([Docker Hub](https://hub.docker.com/), GitLab Container Registry, etc); public or private).

In short, it allows you to:
- List Docker image tags.  
e.g. `dockry ls alpine`, `dockry ls gitlab.example.com:4567/group/project --limit=10`

(see also `dockry ll` in [Usage](#usage))

- Inspect Docker image(s) without `docker pull`ing.  
e.g. `dockry inspect node:latest`  

TIP: Use `--format=`[`<go-template>`](https://golang.org/pkg/text/template/) to customize output.     
For example, to get a **digest** of an image:  
`dockry inspect node:latest --format='{{.name}}@{{.digest}}'`  
(or simply `dockry digest --fq node:latest`) 

- Delete Docker image(s).  
e.g. `dockry rm gitlab.example.com:4567/group/project@sha256:661a5a8...`

## Installation

#### macOS

```sh
curl -sSL https://github.com/shyiko/dockry/releases/download/0.1.0/dockry-0.1.0-darwin-amd64 \
  -o dockry && chmod a+x dockry && sudo mv dockry /usr/local/bin/  
``` 

Verify PGP signature (optional but recommended):

```    
curl -sSL https://github.com/shyiko/dockry/releases/download/0.1.0/dockry-0.1.0-darwin-amd64.asc \
   -o dockry.asc
curl -sS https://keybase.io/shyiko/pgp_keys.asc | gpg --import
gpg --verify dockry.asc /usr/local/bin/dockry
```  

> `gpg` can be installed with `brew install gnupg`

#### Linux

```
curl -sSL https://github.com/shyiko/dockry/releases/download/0.1.0/dockry-0.1.0-linux-amd64 \
  -o dockry && chmod a+x dockry && sudo mv dockry /usr/local/bin/  
```

Verify PGP signature (optional but recommended):

```    
curl -sSL https://github.com/shyiko/dockry/releases/download/0.1.0/dockry-0.1.0-linux-amd64.asc \
  -o dockry.asc
curl -sS https://keybase.io/shyiko/pgp_keys.asc | gpg --import
gpg --verify dockry.asc /usr/local/bin/dockry
```  

#### Windows

Download executable from the [Releases](https://github.com/shyiko/dockry/releases) page.

## Usage

> Depending on weather you are trying to access public or private registry/repo you may need either to
`docker login` (e.g. `docker login gitlab.example.com:4567` if `dockry ls gitlab.example.com:4567/group/project` fails with 401 UNAUTHORIZED) or use `dockry --user=username:password_or_token ...`.

```sh
# list all alpine:* tags
$ dockry ls alpine
latest
edge
3.7
3.6
3.5
3.4
3.3
3.2
3.1
2.7
2.6

# list last 2 mysql images 
# (output fully-qualified names (ready to copy&paste to `docker pull ...`)) 
$ dockry ls mysql --fq --limit=2
mysql:latest
mysql:8

# pretty print 
$ dockry ll azul/zulu-openjdk --limit=3 

master (linux/amd64)  151 MB  3 months ago
latest (linux/amd64)  159 MB  6 days ago
9u04 (linux/amd64)    267 MB  6 days ago

# same as above
$ dockry inspect $(dockry ls alpine --fq --limit=3)
    --format=$'{{.tag}} ({{platform .}})\t{{.downloadSize | hsize}}\t{{.timestamp | hsince}}'

# same as above
$ for image in $(dockry ls alpine --fq --limit=3); do
  dockry inspect $image \
    --format=$'{{.tag}} ({{platform .}})\t{{.downloadSize | hsize}}\t{{.timestamp | hsince}}' 
  done

# inspect image without `docker pull`ing
$ dockry inspect node:6.9.1
[
  {
    "name": "node",
    "tag": "6.9.1",
    "digest": "sha256:661a5a830a072c550ad8ad089d212867d0312c28f2992c01989f6c2789925f10",
    "downloadSize": 256247325,
    "os": "linux",
    "arch": "amd64",
    "timestamp": "2016-11-23T19:20:07.81981642Z",
    "config": {
      "cmd": [
        "node"
      ],
      "env": {
        "NODE_VERSION": "6.9.1",
        "NPM_CONFIG_LOGLEVEL": "info",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      }
    }
  }
]
    
# output fully-qualified digest of an image
$ dockry digest --fq shyiko/openvpn:2.4.0_easyrsa-3.0.3
shyiko/openvpn@sha256:5ff43da1e85f8f5fe43aa7d609946d9ceb8ca0a7665cf4bbedc82d840428a8ff

# same as above
$ dockry inspect shyiko/openvpn:2.4.0_easyrsa-3.0.3 --format='{{.name}}@{{.digest}}'

# image(s) can only be deleted using a digest 
# (there is no such thing as "to remove a tag" in Docker Registry V2)
# no tag->digest auto-resolution is taking place so that implications of rm operation would be clear
$ dockry rm $(dockry digest --fq gitlab.example.com:4567/group/project:experimental)
```

## `dockry inspect` output

> (fields marked with \* are never empty and thus never omitted)  

```js
[
  {
    "name": string*,
    "tag": string,
    "digest": string*,
    "downloadSize": number*,
    "os": string*,
    "osVersion": string,
    "osFeature": []string,
    "arch": string*,
    "cpuVariant": string,
    "cpuFeature": []string,
    "timestamp": string_containing_date_in_iso8601*,
    "config": { 
      // Dockerfile instructions
      "cmd": []string,
      "entrypoint": []string,
      "env": map[string]string,
      "expose": []string,
      "label": map[string]string,
      "onbuild": []string,
      "shell": []string,
      "user": string,
      "volume": []string,
      "workdir": string
    }*
  },
  ...
]
```

> (for more information see `dockry --help`)

#### <kbd>Tab</kbd> completion

```sh
# bash
source <(dockry completion bash)

# zsh
source <(dockry completion zsh)
```

## Development

> PREREQUISITE: [go1.9](https://golang.org/dl/)+.

```sh
git clone https://github.com/shyiko/dockry $GOPATH/src/github.com/shyiko/dockry 
cd $GOPATH/src/github.com/shyiko/dockry
make fetch

go run dockry.go
```

## Legal

All code, unless specified otherwise, is licensed under the [MIT](https://opensource.org/licenses/MIT) license.  
Copyright (c) 2018 Stanley Shyiko.

