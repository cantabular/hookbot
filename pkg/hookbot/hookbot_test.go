package hookbot

import "testing"

// TestPubSub checks that messages are delivered when (pub|sub) is absent.
func TestPubSub(t *testing.T) {
	var messages chan Message

	func() {
		hookbot := New(TEST_KEY)
		defer hookbot.Shutdown()

		messages = hookbot.Add("test/topic").c

		w, r := MakeRequest("POST", "/test/topic", "MESSAGE")
		token := Sha256HMAC(TEST_KEY, "/test/topic")
		r.SetBasicAuth(token, "")

		hookbot.ServeHTTP(w, r)
	}()

	checkDelivered := func(c chan Message, expected string) {
		select {
		case m := <-c:
			if string(m.Body) != expected {
				t.Errorf("m != %s (=%q)", expected, string(m.Body))
			}
		default:
			t.Fatalf("Message not delivered correctly: %q", expected)
		}
	}

	checkDelivered(messages, "MESSAGE")
}
