package rfc7235

import (
	"reflect"
	"testing"
)

// more test cases available at http://test.greenbytes.de/tech/tc/httpauth
func TestParseWWWAuthenticate(t *testing.T) {
	assertWWWAuthenticateParsedAs(t,
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:shyiko/node:pull"`,
		[]WWWAuthenticateChallenge{
			{"bearer", map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:shyiko/node:pull",
			}},
		},
	)
	assertWWWAuthenticateParsedAs(t,
		`Bearer`,
		[]WWWAuthenticateChallenge{
			{"bearer", nil},
		},
	)
	assertWWWAuthenticateParsedAs(t,
		`Bearer , , service=registry.docker.io,
op="auth,auth-int",,
, , Scope="repository:\"shyiko/node\":pull",b=0, Basic  x=, Digest`,
		[]WWWAuthenticateChallenge{
			{"bearer", map[string]string{
				"service": "registry.docker.io",
				"op":      "auth,auth-int",
				"scope":   `repository:\"shyiko/node\":pull`,
				"b":       "0",
			}},
			{"basic", map[string]string{
				"x": "",
			}},
			{"digest", nil},
		},
	)
}

func assertWWWAuthenticateParsedAs(t *testing.T, val string, expected []WWWAuthenticateChallenge) {
	actual, err := ParseWWWAuthenticate(val)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("\nactual:   %#v\n!=\nexpected: %#v", actual, expected)
	}
}
