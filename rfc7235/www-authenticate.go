package rfc7235

import (
	"regexp"
	"strings"
)

// https://tools.ietf.org/html/rfc7235#section-4.1
type WWWAuthenticateChallenge struct {
	Scheme string            // in lower-case
	Params map[string]string // keys are in lower-case
}

// use https://regexr.com/ to understand
var regex = regexp.MustCompile(`([^\s=,]+)(?:(?:\s+([^\s=,]+))?=(?:([^\s",]+)|"((?:[^"\\]|\\.)*)")?)?`)

func ParseWWWAuthenticate(val string) ([]WWWAuthenticateChallenge, error) {
	submatches := regex.FindAllStringSubmatch(val, -1)
	var cc []WWWAuthenticateChallenge
	for _, submatch := range submatches {
		// group 1 - scheme or param name
		// group 2 - param name (not empty only when scheme is present)
		// group 3 - param value (unquoted)
		// group 4 - param value (quoted)
		scheme := submatch[1]
		param := submatch[2]
		paramValue := submatch[3]
		if paramValue == "" {
			paramValue = submatch[4]
		}
		if param == "" {
			if scheme != submatch[0] && len(cc) != 0 {
				i := len(cc) - 1
				c := cc[i]
				if c.Params == nil {
					c.Params = make(map[string]string)
					cc[i] = c
				}
				c.Params[strings.ToLower(scheme)] = paramValue
			} else {
				cc = append(cc, WWWAuthenticateChallenge{strings.ToLower(scheme), nil})
			}
		} else if param != "" {
			cc = append(cc, WWWAuthenticateChallenge{strings.ToLower(scheme), map[string]string{
				strings.ToLower(param): paramValue,
			}})
		}
	}
	return cc, nil
}

// "scheme1 a=b, scheme2 c=d, scheme1 e=f"
// ->
// "scheme2 c=d, scheme1 e=f" ("scheme1 a=b" gets dropped, i.e. last entry wins)
func ParseWWWAuthenticateToMap(val string) (map[string]WWWAuthenticateChallenge, error) {
	cc, err := ParseWWWAuthenticate(val)
	if err != nil {
		return nil, err
	}
	m := make(map[string]WWWAuthenticateChallenge)
	for _, c := range cc {
		m[c.Scheme] = c
	}
	return m, nil
}
