package hookbot

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type Message struct {
	Topic string
	Body  []byte

	// Returns true if message is in flight, false if dropped.
	Sent chan bool // Signalled when messages have been strobed.
}

type Listener struct {
	Topic string
	c     chan Message
	ready chan struct{} // Closed when c is subscribed.
	dead  chan struct{} // Closed when c disconnects.
}

type Hookbot struct {
	key string

	wg       *sync.WaitGroup
	shutdown chan struct{}

	http.Handler

	message                  chan Message
	addListener, delListener chan Listener

	routers []Router

	// Statistics modified using atomic.AddInt64().
	// Recorded to the log by ShowStatus().
	listeners, publish, dropP, sends, dropS int64
}

func New(key string) *Hookbot {
	h := &Hookbot{
		key: key,

		wg:       &sync.WaitGroup{},
		shutdown: make(chan struct{}),

		message:     make(chan Message, 1),
		addListener: make(chan Listener, 1),
		delListener: make(chan Listener, 1),
	}

	sub := WebsocketHandlerFunc(h.ServeSubscribe)
	pub := http.HandlerFunc(h.ServePublish)

	mux := http.NewServeMux()
	mux.Handle("/sub/", h.KeyChecker(sub))
	mux.Handle("/pub/", h.KeyChecker(pub))

	mux.Handle("/unsafe/sub/", RequireUnsafeHeader(h.KeyChecker(sub)))
	mux.Handle("/unsafe/pub/", pub)

	mux.Handle("/", h.KeyChecker(h.BothPubSub(pub, sub)))

	h.Handler = mux

	h.wg.Add(1)
	go h.Loop()

	h.wg.Add(1)
	go h.ShowStatus(time.Minute)

	return h
}

// BothPubSub is an endpoint which supports either publishing or subscribing.
// If it is a POST request, it is publishing, otherwise it is subscribing.
func (h *Hookbot) BothPubSub(pub, sub http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			pub.ServeHTTP(w, r)
		case "GET":
			sub.ServeHTTP(w, r)
		default:
			http.Error(w, "Not Implemented", http.StatusNotImplemented)
		}
	})
}

// Every `period`, log a status line showing number of connected listeners,
// dropped messages, etc.
func (h *Hookbot) ShowStatus(period time.Duration) {
	defer h.wg.Done()
	ticker := time.NewTicker(period)
	var ll, lp, ls, ldP, ldS int64

	for {
		select {
		case <-ticker.C:
			l := atomic.LoadInt64(&h.listeners)
			p := atomic.LoadInt64(&h.publish)
			s := atomic.LoadInt64(&h.sends)
			dP := atomic.LoadInt64(&h.dropP)
			dS := atomic.LoadInt64(&h.dropS)

			log.Printf("Listeners %5d [%+5d] pub %5d [%+5d] (d %5d [%+5d])"+
				" send %8d [%+7d] (d %5d [%+5d])",
				l, l-ll, p, p-lp, dP, dP-ldP, s, s-ls, dS, dS-ldS)

			ll, lp, ls, ldP, ldS = l, p, s, dP, dS
		case <-h.shutdown:
			return
		}
	}
}

// Shut down main loop and wait for all in-flight messages to send or timeout
func (h *Hookbot) Shutdown() {
	close(h.shutdown)
	h.wg.Wait()
}

// Returns "true" if fullTopic ends with a "/".
// Also supports topics ending with ?recursive to support legacy infrastructure.
func recursive(fullTopic string) (topic string, isRecursive bool) {
	// Legacy: topics ending in ?recursive are recursive.
	if strings.HasSuffix(fullTopic, "?recursive") {
		return fullTopic[:len(fullTopic)-len("?recursive")], true
	}

	// Topics ending in "/" are recursive
	if strings.HasSuffix(fullTopic, "/") {
		return fullTopic, true
	}

	return fullTopic, false
}

// Represents one {listener, message} pair, which is used for buffering and
// timing out messages in TimeoutSendWorker.
type MessageListener struct {
	l Listener
	m *Message
}

// Analogous to MessageListener, but to represent {listeners, message} on a
// similar worker.
type MessageListeners struct {
	interested map[Listener]struct{}
	m          *Message
}

// Timeout for a ServeSubscribe to accept a message before it gets dropped.
const timeout = 1 * time.Second

// The TimeoutSendWorker passes messages from r onto individual listeners.
// It is responsible for dropping messages if the receiver can't keep up fast
// enough, or if the receiver disappears.
// Fun history: we used to spawn a goroutine per message, but this wasted large
// amounts of memory and performance.
func (h *Hookbot) TimeoutSendWorker(r chan MessageListener) {
	for lm := range r {
		select {
		case lm.l.c <- *lm.m:
			// Message successfully handed off to websocket writer.
			atomic.AddInt64(&h.sends, 1)

		case <-time.After(timeout):
			// Websocket writer's buffer was full.
			atomic.AddInt64(&h.dropS, 1)

		case <-lm.l.dead:
			// Listener went away.
		}
	}
}

// Manage fanout from h.message onto listeners
func (h *Hookbot) Loop() {
	defer h.wg.Done()

	cMessageListener := make(chan MessageListener, 1000)
	defer close(cMessageListener)

	// Wait for the cMessageListeners goroutine to finish before closing
	// cMessageListener
	var wgMessageListeners sync.WaitGroup
	defer wgMessageListeners.Wait()

	cMessageListeners := make(chan MessageListeners, 100)
	defer close(cMessageListeners)

	const W = 10 // Number of worker threads
	for i := 0; i < W; i++ {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.TimeoutSendWorker(cMessageListener)
		}()
	}

	wgMessageListeners.Add(1)
	go func() {
		defer wgMessageListeners.Done()

		// Fanout `cMessageListeners` onto available `TimeoutSendWorker`s
		for lms := range cMessageListeners {
			for l := range lms.interested {
				cMessageListener <- MessageListener{l, lms.m}
			}
		}
	}()

	listeners := map[string]map[Listener]struct{}{}

	// Determine the set of interested listeners for a given topic.
	interested := func(topic string) map[Listener]struct{} {
		ls := map[Listener]struct{}{}

		for l := range listeners[topic] {
			ls[l] = struct{}{}
		}

		for fullCandidateTopic, candidateLs := range listeners {
			candidateTopic, isRec := recursive(fullCandidateTopic)
			if !isRec {
				continue
			}

			if !strings.HasPrefix(topic, candidateTopic) {
				continue
			}
			for l := range candidateLs {
				ls[l] = struct{}{}
			}
		}
		return ls
	}

	for {
		select {
		case m := <-h.message:
			// Main message send.

			select {
			case cMessageListeners <- MessageListeners{interested(m.Topic), &m}:
				// A message making it onto `cMessageListeners` is considered
				// "sent" in that it has successfully entered the queue to be
				// sent. It can still be dropped if a receiver is sufficiently
				// slow to free up buffer space for the message.
				atomic.AddInt64(&h.publish, 1)
				m.Sent <- true
			default:
				// In this case, the `cMessageListeners` buffer is full.
				// This can happen if all TimeoutSendWorkers are full and the
				// `cMessageListeners` channel buffer is also full.
				atomic.AddInt64(&h.dropP, 1)
				m.Sent <- false
			}

		case l := <-h.addListener:
			// New listener appears
			atomic.AddInt64(&h.listeners, 1)

			if _, ok := listeners[l.Topic]; !ok {
				listeners[l.Topic] = map[Listener]struct{}{}
			}
			listeners[l.Topic][l] = struct{}{}
			close(l.ready)

		case l := <-h.delListener:
			// Listener disappears
			atomic.AddInt64(&h.listeners, -1)

			delete(listeners[l.Topic], l)
			if len(listeners[l.Topic]) == 0 {
				delete(listeners, l.Topic)
			}

		case <-h.shutdown:
			// Signalled to shut down cleanly.
			return
		}
	}
}

// Return a new Listener which receives messages for `topic`.
func (h *Hookbot) Add(topic string) Listener {
	ready := make(chan struct{})
	l := Listener{
		Topic: topic,

		c:     make(chan Message, 1),
		ready: ready,
		dead:  make(chan struct{}),
	}
	h.addListener <- l
	<-ready
	return l
}

// Process messages for one router (one goroutine per topic)
func (h *Hookbot) AddRouter(r Router) {
	for _, topic := range r.Topics() {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()

			l := h.Add(topic)
			for m := range l.c {
				r.Route(m, h.Publish)
			}
		}()
	}
}

// Remove `l` from the set of interested listeners.
func (h *Hookbot) Del(l Listener) {
	close(l.dead)
	h.delListener <- l
}

// The topic is everything after the "/pub/" or "/sub/"
// Do not capture the "/unsafe". See note in `Topic()`.
var TopicRE *regexp.Regexp = regexp.MustCompile("^(?:/unsafe)?/(?:pub|sub)/(.*)$")

func Topic(r *http.Request) string {
	if !TopicRE.MatchString(r.URL.Path) {
		// No match. (pub/sub) not specified.
		// The whole URI (minus leading /) is the topic.
		return strings.TrimPrefix(r.URL.Path, "/")
	}
	m := TopicRE.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return ""
	}
	topic := m[1]
	if IsUnsafeRequest(r) {
		return "/unsafe/" + topic
	}
	return topic
}

// Publish a message via HTTP POST.
func (h *Hookbot) ServePublish(w http.ResponseWriter, r *http.Request) {

	topic := Topic(r)

	var (
		body []byte
		err  error
	)

	body, err = ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Error in ServePublish reading body:", err)
		http.Error(w, "500 Internal Server Error",
			http.StatusInternalServerError)
		return
	}

	extraMetadata := r.URL.Query()["extra-metadata"]
	if len(extraMetadata) > 0 {
		switch extraMetadata[0] {
		case "github":

			body, err = json.Marshal(map[string]interface{}{
				"Signature": r.Header.Get("X-Hub-Signature-256"),
				"Event":     r.Header.Get("X-GitHub-Event"),
				"Delivery":  r.Header.Get("X-GitHub-Delivery"),
				"Payload":   body,
			})

			if err != nil {
				log.Println("Error in ServePublish serializing payload:", err)
				http.Error(w, "500 Internal Server Error",
					http.StatusInternalServerError)
			}

		default:
			http.Error(w, "400 Bad Request (bad ?extra-metadata=)",
				http.StatusBadRequest)
			return
		}
	}

	log.Printf("Publish %q", topic)

	ok := h.Publish(Message{Topic: topic, Body: body})

	if !ok {
		http.Error(w, "Timeout in send", http.StatusServiceUnavailable)
		return
	}

	fmt.Fprintln(w, "OK")
}

// Blocks until message has been published.
func (h *Hookbot) Publish(m Message) bool {
	sent := make(chan bool)
	m.Sent = sent

	select {
	case h.message <- m:
	case <-time.After(timeout):
		atomic.AddInt64(&h.dropP, 1)
		return false
	}

	return <-sent
}

// Subscribe to message via HTTP websocket.
func (h *Hookbot) ServeSubscribe(conn *websocket.Conn, r *http.Request) {
	topic := Topic(r)

	listener := h.Add(topic)
	defer h.Del(listener)

	closed := make(chan struct{})

	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				conn.Close()
				return
			}
		}
	}()

	var message Message

	for {
		select {
		case message = <-listener.c:
		case <-closed:
			return
		}

		conn.SetWriteDeadline(time.Now().Add(90 * time.Second))
		_, isRecursive := recursive(topic)
		msgBytes := []byte{}
		if isRecursive {
			msgBytes = append(msgBytes, message.Topic...)
			msgBytes = append(msgBytes, '\x00')
			msgBytes = append(msgBytes, message.Body...)
		} else {
			msgBytes = message.Body
		}
		err := conn.WriteMessage(websocket.BinaryMessage, msgBytes)
		switch {
		case err == io.EOF || IsConnectionClose(err):
			return
		case err != nil:
			log.Printf("Error in conn.WriteMessage: %v", err)
			return
		}
	}
}

func IsConnectionClose(err error) bool {
	if err == nil {
		return false
	}
	str := err.Error()
	switch {
	case strings.HasSuffix(str, "broken pipe"):
		return true
	case strings.HasSuffix(str, "connection reset by peer"):
		return true
	case strings.HasSuffix(str, "use of closed network connection"):
		return true
	}
	return false
}
