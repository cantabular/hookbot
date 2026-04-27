package hookbot

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	TEST_GITHUB_SECRET = "github_secret"
	TEST_KEY           = "key"
)

func MakeRequest(method, url, body string) (w *httptest.ResponseRecorder, r *http.Request) {
	w = httptest.NewRecorder()
	bodyReader := bytes.NewReader([]byte(body))
	r, _ = http.NewRequest(method, "http://localhost"+url, bodyReader)
	return w, r
}

// Bad authentication should cause a 404 not found.
func TestAuthMissingFail(t *testing.T) {
	w, r := MakeRequest("POST", "/pub/", "MESSAGE")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status code != 404 (= %v)", w.Code)
	}
}

// Invalid secret authentication should return 404 Not Found.
func TestAuthInvalidSecret(t *testing.T) {
	w, r := MakeRequest("POST", "/pub/", "MESSAGE")

	token := Sha256HMAC(TEST_KEY, "/pub/not/the/same/as/above") // bad secret
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status code != 404 (= %v)", w.Code)
	}
}

// Valid secret authentication should return 200 OK
func TestAuthSuccess(t *testing.T) {
	w, r := MakeRequest("POST", "/pub/place", "MESSAGE")

	token := Sha256HMAC(TEST_KEY, "/pub/place")
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusOK {
		t.Errorf("Status code != 200 (= %v)", w.Code)
	}
}

// TestAuthPubSub checks that a secret created with no pub/sub is valid for both.
func TestAuthPubSub(t *testing.T) {

	// Valid for both pub and sub, for lack of {/pub,/sub} prefix
	token := Sha256HMAC(TEST_KEY, "/place")

	w, r := MakeRequest("POST", "/pub/place", "MESSAGE")
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()
		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusOK {
		t.Errorf("Status code != 200 (= %v)", w.Code)
	}

	w, r = MakeRequest("GET", "/sub/place", "")
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()
		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code != 400 (= %v)", w.Code)
	}

	response := string(w.Body.Bytes())
	if response != "Bad Request\n" {
		t.Errorf("Response body incorrect, got: %q", response)
	}
}

// Valid secret authentication should return 200 OK
func TestAuthSuccessSubstring(t *testing.T) {
	w, r := MakeRequest("POST", "/pub/place/sub/sub/sub", "MESSAGE")

	token := Sha256HMAC(TEST_KEY, "/pub/place/")
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusOK {
		t.Errorf("Status code != 200 (= %v)", w.Code)
	}
}

// Failed secret authentication should not return 200 OK
// Fails because po is not a entire step upwards from pub/post
func TestAuthFailSubstring(t *testing.T) {
	w, r := MakeRequest("POST", "/pub/post", "MESSAGE")

	token := Sha256HMAC(TEST_KEY, "/pub/po")
	r.SetBasicAuth(token, "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code == http.StatusOK {
		t.Errorf("Status code == 200 (= %v)", w.Code)
	}
}

// Unsafe pub should always succeed, without credentials
func TestUnsafePub(t *testing.T) {

	run := func(iteration int) {

		var c chan Message

		func() {
			hookbot := New(TEST_KEY)
			defer hookbot.Shutdown()

			msgs := hookbot.Add("/unsafe/")
			c = msgs.c

			w, r := MakeRequest("POST", "/unsafe/pub/", "MESSAGE")

			hookbot.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("Status code != 200 (= %v)", w.Code)
			}
		}()

		// Message should have been delivered by the time we see
		// hookbot.Shutdown().
		select {
		case <-c:
		default:
			t.Fatalf("Message not delivered (iteration %v)", iteration)
		}
	}

	// Run the test repeatedly to search for races.
	// (I was hitting them ~1 per few before.)
	for i := 0; i < 10; i++ {
		run(i)
	}
}

// It should not be possible to subscribe to an unsafe channel unless you
// supply an appropriate header.
func TestUnsafeSubMissingHeader(t *testing.T) {

	w, r := MakeRequest("GET", "/unsafe/sub/", "")

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code != 400 (= %v)", w.Code)
	}

	response := string(w.Body.Bytes())
	if response != "400 Bad Request. X-Hookbot-Unsafe-Is-Ok header required.\n" {
		t.Errorf("Response body incorrect, got: %q", response)
	}
}

type ResponseRecorderWithHijack struct {
	*httptest.ResponseRecorder
}

var ErrCannotHijack = fmt.Errorf("cannot hijack ResponseRecorder")
var _ http.Hijacker = &ResponseRecorderWithHijack{}

func (r *ResponseRecorderWithHijack) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, ErrCannotHijack
}

// If the molly guard is removed (see TestUnsafeSubMissingHeader), the request
// should succeed (in this case, we get a protocol error because we tried
// subsequently to establish a websocket)
func TestUnsafeSubWithHeader(t *testing.T) {

	w, r := MakeRequest("GET", "/unsafe/sub/", "")

	r.Header.Add("X-Hookbot-Unsafe-Is-Ok",
		"I understand the security implications")

	wHijack := &ResponseRecorderWithHijack{w}

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		hookbot.ServeHTTP(wHijack, r)
	}()

	// This is pinned according to how gorilla/websocket responds when given
	// a non-websocket connection. That's because we made it through any layers
	// of authentication/protection and tried to initiate a websocket
	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code != 400 (= %v)", w.Code)
	}

	// Again, this is just how gorilla/websocket responds.
	response := string(w.Body.Bytes())
	if response != "Bad Request\n" {
		t.Errorf("Response body incorrect, got: %q", response)
	}
}
