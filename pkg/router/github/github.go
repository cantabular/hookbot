package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/sensiblecodeio/hookbot/pkg/hookbot"
	"github.com/sensiblecodeio/hookbot/pkg/listen"
)

var RegexParseHeader = regexp.MustCompile("^\\s*([^\\:]+)\\s*:\\s*(.*)$")

func MustParseHeader(header string) (string, string) {
	if !RegexParseHeader.MatchString(header) {
		log.Fatalf("Unable to parse header: %v (re: %v)", header,
			RegexParseHeader.String())
		return "", ""
	}

	parts := RegexParseHeader.FindStringSubmatch(header)
	return parts[1], parts[2]
}

func MustParseHeaders(headerStrings []string) http.Header {
	headers := http.Header{}

	for _, h := range headerStrings {
		key, value := MustParseHeader(h)
		headers.Set(key, value)
	}

	return headers
}

func MustMakeHeader(
	target *url.URL, origin string, headerStrings []string,
) http.Header {

	header := MustParseHeaders(headerStrings)
	if origin == "samehost" {
		origin = "//" + target.Host
	}

	header.Add("Origin", origin)
	header.Add("X-Hookbot-Unsafe-Is-Ok",
		"I understand the security implications")

	return header
}

func ActionRoute(_ context.Context, c *cli.Command) error {

	target, err := url.Parse(c.String("monitor-url"))
	if err != nil {
		log.Fatalf("Failed to parse %q as URL: %v", c.String("monitor-url"), err)
	}

	origin := c.String("origin")

	header := MustMakeHeader(target, origin, c.StringSlice("header"))
	finish := make(chan struct{})

	messages, errors := listen.RetryingWatch(target.String(), header, finish)

	outbound := make(chan listen.Message, 1)

	publish := func(m hookbot.Message) bool {
		token := Sha1HMAC(c.String("key"), []byte(m.Topic))

		outURL := fmt.Sprintf("https://%v@%v/pub/%s", token, target.Host, m.Topic)

		body := ioutil.NopCloser(bytes.NewBuffer(m.Body))

		out, err := http.NewRequest("POST", outURL, body)
		if err != nil {
			log.Printf("Failed to construct outbound req: %v", err)
			return false
		}
		out.SetBasicAuth(token, "")

		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			log.Printf("Failed to transmit: %v", err)
			return false
		}
		log.Printf("Transmit: %v %v", resp.StatusCode, outURL)
		return true
	}

	go func() {
		for err := range errors {
			log.Printf("Encountered error in Watch: %v", err)
		}
	}()

	router := &Router{}

	for mBytes := range messages {
		log.Printf("Receive message")

		parts := bytes.Split(mBytes, []byte{0})
		topic := parts[0]
		body := parts[1]

		if !IsValidGithubSignature(c.String("github-secret"), body) {
			log.Printf("Reject github signature")
			continue
		}

		m := hookbot.Message{Topic: string(topic), Body: body}
		router.Route(m, publish)
	}
	close(outbound)
	return nil
}

type Event struct {
	Type string

	Repository *Repository `json:"repository"`
	Pusher     *Pusher     `json:"pusher"`

	Ref    string `json:"ref"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func (e *Event) Branch() string {
	return strings.TrimPrefix(e.Ref, "refs/heads/")
}

type Pusher struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Repository struct {
	FullName string `json:"full_name"`
}

type Router struct{}

func (r *Router) Name() string {
	return "github"
}

func (r *Router) Topics() []string {
	return []string{"/unsafe/github.com/"}
}

func (r *Router) Route(in hookbot.Message, publish func(hookbot.Message) bool) {

	log.Printf("route github: %q", in.Topic)

	type GithubMessage struct {
		Event, Signature string
		Payload          []byte
	}

	var m GithubMessage

	err := json.Unmarshal(in.Body, &m)
	if err != nil {
		log.Printf("Failed to unmarshal message in IsValidGithubSignature: %v",
			err)
		return
	}

	var event Event
	event.Type = m.Event

	err = json.Unmarshal(m.Payload, &event)
	if err != nil {
		log.Printf("Route: error in json.Unmarshal: %v", err)
		return
	}

	if event.Repository == nil || event.Repository.FullName == "" {
		log.Printf("Could not identify repository for event %v", event.Type)
		return
	}

	repo := event.Repository.FullName
	branch := event.Branch()

	who := "<unknown>"
	if event.Pusher != nil {
		who = event.Pusher.Name
	}

	msgBytes, err := json.Marshal(map[string]string{
		"Type":   event.Type,
		"Repo":   repo,
		"Branch": branch,
		"SHA":    event.After,
		"Who":    who,
	})
	if err != nil {
		log.Printf("Failed to marshal Update: %v", err)
		return
	}

	switch event.Type {
	case "push":
		topicFmt := "github.com/repo/%s/branch/%s"

		// May fail
		_ = publish(hookbot.Message{
			Topic: fmt.Sprintf(topicFmt, repo, branch),
			Body:  msgBytes,
		})
	default:
		log.Printf("Unhandled event type: %v", event.Type)
		return
	}

}

func init() {
	hookbot.RegisterRouter(&Router{})
}
