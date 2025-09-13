package hookbot

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func Sha1HMAC(key, payload string) string {
	mac := hmac.New(sha1.New, []byte(key))
	_, _ = mac.Write([]byte(payload))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func SecureEqual(x, y string) bool {
	if subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1 {
		return true
	}
	return false
}

func subpaths(s string) []string {
	// Return all subpaths terminating in a "/" and itself.
	// i.e. foo/bar/baz returns foo/ foo/bar/ and foo/bar/baz
	// Happens to return itself twice if it ends in a /
	slashes := strings.SplitAfter(s, "/")
	output := []string{}
	for i, _ := range slashes {
		output = append(
			output,
			strings.Join(slashes[0:i+1], ""),
		)
	}
	return output
}

func (h *Hookbot) IsKeyOK(w http.ResponseWriter, r *http.Request) bool {

	authorization := r.Header.Get("Authorization")
	fields := strings.Fields(authorization)

	var givenMac string

	if len(fields) != 2 {
		authParam := r.URL.Query()["auth"]
		if len(authParam) != 1 {
			return false
		}
		givenMac = authParam[0]
	} else {

		authType, givenKey := fields[0], fields[1]

		switch strings.ToLower(authType) {
		default:
			return false // Not understood
		case "basic":
			var ok bool
			givenMac, _, ok = r.BasicAuth()
			if !ok {
				return false
			}

		case "bearer":
			givenMac = givenKey // No processing required
		}
	}

	// Try all subpaths and see if any of them matches the given MAC.
	for _, subpath := range subpaths(r.URL.Path) {
		expectedMac := Sha1HMAC(h.key, subpath)
		if SecureEqual(givenMac, expectedMac) {
			return true
		}

		// See if HMAC matches the URL without the {/pub,/sub} prefix.
		// These tokens are valid for both pub and sub.
		expectedMac = Sha1HMAC(h.key, noPrefix(subpath))
		if SecureEqual(givenMac, expectedMac) {
			return true
		}
	}

	return false
}

func noPrefix(withPrefix string) string {
	withPrefix = strings.TrimPrefix(withPrefix, "/pub")
	withPrefix = strings.TrimPrefix(withPrefix, "/sub")
	return withPrefix
}

var UnsafeURI = regexp.MustCompile("^/unsafe/(pub|sub)/.*")

// Unsafe requests are those with URIs which have /unsafe/ as the second
// path component.
func IsUnsafeRequest(r *http.Request) bool {
	return UnsafeURI.MatchString(r.URL.Path)
}

func RequireUnsafeHeader(wrapped http.Handler) http.HandlerFunc {
	const ErrMsg = "400 Bad Request. X-Hookbot-Unsafe-Is-Ok header required."

	return func(w http.ResponseWriter, r *http.Request) {

		values, have_unsafe_header := r.Header["X-Hookbot-Unsafe-Is-Ok"]

		if IsUnsafeRequest(r) {
			// "X-Hookbot-Unsafe-Is-Ok" header required
			if !have_unsafe_header {
				http.Error(w, ErrMsg, http.StatusBadRequest)
				return
			}

			// Unsafe URLs can be published to by anyone on the internet
			// without a valid key and it is *your* responsibility to check
			// the key. This is so that the security checking can happen
			// in another component (e.g, a thing that understand's github's
			// signing mechanism). The header is required so that people
			// don't mistakenly specify an unsafe URL in a component which
			// must not use one.
			if values[0] != "I understand the security implications" {
				http.Error(w, ErrMsg, http.StatusBadRequest)
				return
			}
		}

		wrapped.ServeHTTP(w, r)
	}
}

func (h *Hookbot) KeyChecker(wrapped http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsUnsafeRequest(r) {
			// Unsafe requests don't check keys. See UnsafeChecker.
			wrapped.ServeHTTP(w, r)
			return
		}

		if !h.IsKeyOK(w, r) {
			w.Header().Add("WWW-Authenticate", `Basic realm="hookbot"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		wrapped.ServeHTTP(w, r)
	}
}
