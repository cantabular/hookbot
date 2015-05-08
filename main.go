package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/codegangsta/cli"
	"github.com/gorilla/websocket"
)

func main() {
	app := cli.NewApp()
	app.Name = "hookbot"
	app.Usage = "turn webhooks into websockets"

	app.Commands = []cli.Command{
		{
			Name:    "serve",
			Aliases: []string{"s"},
			Usage:   "start a hookbot instance, listening on http",
			Action:  ActionServe,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "bind, b",
					Value: ":8080",
					Usage: "address to listen on",
				},
			},
		},
		{
			Name:    "make-tokens",
			Aliases: []string{"t"},
			Usage:   "given a list of URIs, generate tokens one per line",
			Action:  ActionMakeTokens,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "bare",
					Usage: "print only tokens (not as basic-auth URLs)",
				},
				cli.StringFlag{
					Name:   "url-base, U",
					Value:  "http://localhost:8080",
					Usage:  "base URL to generate for (not included in hmac)",
					EnvVar: "HOOKBOT_URL_BASE",
				},
			},
		},
		{
			Name:    "copy",
			Aliases: []string{"cp"},
			Usage:   "act as a hookbot server, relaying messages from a specified endpoint",
			Action:  ActionCopy,
		},
	}

	app.RunAndExitOnError()
}

func MustGetKeysFromEnv() (string, string) {
	var (
		key           = os.Getenv("HOOKBOT_KEY")
		github_secret = os.Getenv("HOOKBOT_GITHUB_SECRET")
	)

	if key == "" || github_secret == "" {
		log.Fatalln("Error: HOOKBOT_KEY or HOOKBOT_GITHUB_SECRET not set")
	}

	return key, github_secret
}

var SubscribeURIRE = regexp.MustCompile("^(?:/unsafe)?/sub")

func ActionMakeTokens(c *cli.Context) {
	key, _ := MustGetKeysFromEnv()
	if len(c.Args()) < 1 {
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	baseStr := c.String("url-base")
	u, err := url.ParseRequestURI(baseStr)
	if err != nil {
		log.Fatal("Unable to parse url-base %q: %v", baseStr, err)
	}

	initialScheme := u.Scheme

	getScheme := func(target string) string {

		scheme := "http"

		secure := "" // if https or wss, "s", "" otherwise.
		switch initialScheme {
		case "https", "wss":
			secure = "s"
		}

		// If it's pub, use http(s), sub ws(s)
		if SubscribeURIRE.MatchString(target) {
			scheme = "ws"
		}
		return scheme + secure
	}

	for _, arg := range c.Args() {
		mac := Sha1HMAC(key, arg)
		if c.Bool("bare") {
			fmt.Println(mac)
		} else {
			u.Scheme = getScheme(arg)
			u.User = url.User(mac)
			u.Path = arg
			fmt.Println(u)
		}
	}
}

func ActionServe(c *cli.Context) {
	key, github_secret := MustGetKeysFromEnv()

	hookbot := NewHookbot(key, github_secret)
	http.Handle("/", hookbot)
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	log.Println("Listening on", c.String("bind"))
	err := http.ListenAndServe(c.String("bind"), nil)
	if err != nil {
		log.Fatal(err)
	}
}

type Message struct {
	Topic string
	Body  []byte
	Done  chan struct{} // signalled when messages have been strobed
	// (this is not the same as when they have been received)
}

type Listener struct {
	Topic string
	c     chan []byte
	ready chan struct{} // closed when c is subscribed
}

type Hookbot struct {
	key, github_secret string

	wg       *sync.WaitGroup
	shutdown chan struct{}

	http.Handler

	message                  chan Message
	addListener, delListener chan Listener
}

func NewHookbot(key, github_secret string) *Hookbot {
	h := &Hookbot{
		key: key, github_secret: github_secret,

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

	// Require the key *and* a declaration that unsafe messages are OK.
	mux.Handle("/unsafe/sub/", RequireUnsafeHeader(h.KeyChecker(sub)))

	// Unsafe can be published to from anywhere, no key required.
	// (so no KeyChecker)
	mux.Handle("/unsafe/pub/", http.HandlerFunc(h.ServePublish))

	h.Handler = mux

	h.wg.Add(1)
	go h.Loop()

	return h
}

var timeout = 1 * time.Second

func TimeoutSend(wg *sync.WaitGroup, c chan []byte, m []byte) {
	defer wg.Done()

	select {
	case c <- m:
	case <-time.After(timeout):
	}
}

// Shut down main loop and wait for all in-flight messages to send or timeout
func (h *Hookbot) Shutdown() {
	close(h.shutdown)
	h.wg.Wait()
}

// Manage fanout from h.message onto listeners
func (h *Hookbot) Loop() {
	defer h.wg.Done()

	listeners := map[Listener]struct{}{}

	for {
		select {
		case m := <-h.message:

			// Strobe all interested listeners
			for listener := range listeners {
				if listener.Topic == m.Topic {
					h.wg.Add(1)
					go TimeoutSend(h.wg, listener.c, m.Body)
				}
			}

			close(m.Done)

		case l := <-h.addListener:
			listeners[l] = struct{}{}
			close(l.ready)
		case l := <-h.delListener:
			delete(listeners, l)
		case <-h.shutdown:
			return
		}
	}
}

func (h *Hookbot) Add(topic string) Listener {
	ready := make(chan struct{})
	l := Listener{
		Topic: topic,
		c:     make(chan []byte, 1),
		ready: ready,
	}
	h.addListener <- l
	<-ready // wait until "c" in the subscribed map, for testing.
	return l
}

func (h *Hookbot) Del(l Listener) {
	h.delListener <- l
}

// The topic is everything after the "/pub/" or "/sub/"
// Do not capture the "/unsafe". See note in `Topic()`.
var TopicRE *regexp.Regexp = regexp.MustCompile("^(?:/unsafe)?/[^/]+/(.*)$")

func Topic(r *http.Request) string {
	m := TopicRE.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return ""
	}
	topic := m[1]
	if IsUnsafeRequest(r) {
		// Note: `topic` cannot start `/unsafe/`, so it's
		// not possible to alias it.
		return "/unsafe/" + topic
	}
	return topic
}

func (h *Hookbot) ServePublish(w http.ResponseWriter, r *http.Request) {

	done := make(chan struct{})

	topic := Topic(r)

	body, err := json.Marshal(RequestJSONMarshaller{r})
	if err != nil {
		log.Println("Error in ServePublish:", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Publish %q", topic)

	h.message <- Message{Topic: topic, Body: body, Done: done}
	fmt.Fprintln(w, "OK")

	// Wait for the listeners to be strobed.
	// This is needed for testing purposes.
	// :-(
	<-done
}

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

	var message []byte

	for {
		select {
		case message = <-listener.c:
		case <-closed:
			log.Printf("Client disconnected")
			return
		}

		conn.SetWriteDeadline(time.Now().Add(90 * time.Second))
		err := conn.WriteMessage(websocket.BinaryMessage, message)
		switch {
		case err == io.EOF:
			return // done
		case err != nil:
			log.Printf("Error in conn.WriteMessage: %v", err)
			return // unknown error
		}
	}
}
