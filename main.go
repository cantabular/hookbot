package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/urfave/cli/v3"

	"github.com/sensiblecodeio/hookbot/pkg/hookbot"
	"github.com/sensiblecodeio/hookbot/pkg/router/github"
)

func main() {
	cmd := cli.Command{
		Name:    "hookbot",
		Usage:   "turn webhooks into websockets",
		Version: "0.16.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "key",
				Usage:   "secret known only for hookbot for URL access control",
				Value:   "<unset>",
				Sources: cli.EnvVars("HOOKBOT_KEY"),
			},
			&cli.StringFlag{
				Name:    "github-secret",
				Usage:   "secret known by github for signing messages",
				Value:   "<unset>",
				Sources: cli.EnvVars("HOOKBOT_GITHUB_SECRET"),
			},
		},

		Commands: []*cli.Command{
			{
				Name:   "serve",
				Usage:  "start a hookbot instance, listening on http",
				Action: ActionServe,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "bind, b",
						Value: ":8080",
						Usage: "address to listen on",
					},
					&cli.StringFlag{
						Name:  "sslkey, k",
						Value: "<unset>",
						Usage: "path to the SSL secret key",
					},
					&cli.StringFlag{
						Name:  "sslcrt, c",
						Value: "<unset>",
						Usage: "path to the SSL compound certificate",
					},
					&cli.StringSliceFlag{
						Name:  "router",
						Usage: "list of routers to enable",
					},
				},
			},
			{
				Name:    "make-tokens",
				Aliases: []string{"t"},
				Usage:   "given a list of URIs, generate tokens one per line",
				Action:  ActionMakeTokens,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "bare",
						Usage: "print only tokens (not as basic-auth URLs)",
					},
					&cli.StringFlag{
						Name:    "url-base, U",
						Value:   "http://localhost:8080",
						Usage:   "base URL to generate for (not included in hmac)",
						Sources: cli.EnvVars("HOOKBOT_URL_BASE"),
					},
				},
			},
			{
				Name:   "route-github",
				Usage:  "route github requests",
				Action: github.ActionRoute,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "monitor-url, u",
						Usage: "URL to monitor",
					},
					&cli.StringFlag{
						Name:    "origin",
						Value:   "samehost",
						Usage:   "URL to use for the origin header ('samehost' is special)",
						Sources: cli.EnvVars("HOOKBOT_ORIGIN"),
					},
					&cli.StringSliceFlag{
						Name:    "header, H",
						Usage:   "headers to pass to the remote",
						Sources: cli.EnvVars("HOOKBOT_HEADER"),
					},
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

var SubscribeURIRE = regexp.MustCompile("^(?:/unsafe)?/sub")

func ActionMakeTokens(_ context.Context, c *cli.Command) error {
	key := c.String("key")
	if key == "<unset>" {
		log.Fatalln("HOOKBOT_KEY not set")
	}

	if c.Args().Len() < 1 {
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	baseStr := c.String("url-base")
	u, err := url.ParseRequestURI(baseStr)
	if err != nil {
		log.Fatalf("Unable to parse url-base %q: %v", baseStr, err)
	}

	initialScheme := u.Scheme

	getScheme := func(initialScheme, target string) string {
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

	for _, arg := range c.Args().Slice() {
		argURL, err := url.Parse(arg)
		if err != nil {
			log.Fatalf("URL %q doesn't parse: %v", arg, err)
		}

		mac := hookbot.Sha1HMAC(key, argURL.Path)
		if c.Bool("bare") {
			fmt.Println(mac)
		} else {
			s := initialScheme
			if argURL.Scheme != "" {
				// If the arg specifies a scheme, it overrides
				// the base scheme.
				s = argURL.Scheme
			}
			u.Scheme = getScheme(s, argURL.Path)

			u.User = url.User(mac)
			if argURL.Host != "" {
				// If the argument uses a new host, use that one.
				u.Host = argURL.Host
			}

			// Preserve the original path, query and fragment.
			u.Path = argURL.Path
			u.RawQuery = argURL.RawQuery
			u.Fragment = argURL.Fragment

			fmt.Println(u)
		}
	}
	return nil
}

func ActionServe(_ context.Context, c *cli.Command) error {
	key := c.String("key")
	if key == "<unset>" {
		log.Fatalln("HOOKBOT_KEY not set")
	}

	hb := hookbot.New(key)

	// Setup routers configured on the command line
	hookbot.ConfigureRouters(c, hb)

	http.Handle("/", hb)
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	log.Println("Listening on", c.String("bind"))

	sslkey := c.String("sslkey")

	var err error

	if sslkey == "<unset>" {
		err = http.ListenAndServe(c.String("bind"), nil)
	} else {
		err = http.ListenAndServeTLS(c.String("bind"), c.String("sslcrt"), c.String("sslkey"), nil)
	}
	if err != nil {
		log.Fatal(err)
	}
	return nil
}
