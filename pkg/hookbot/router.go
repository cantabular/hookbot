package hookbot

import (
	"log"

	"github.com/urfave/cli/v3"
)

type Router interface {
	Name() string
	Topics() []string
	Route(in Message, publish func(Message) bool)
}

var availableRouters []Router

func RegisterRouter(router Router) {
	availableRouters = append(availableRouters, router)
}

func ConfigureRouters(c *cli.Command, h *Hookbot) {
	enabledRouters := map[string]struct{}{}

	for _, r := range c.StringSlice("router") {
		log.Println("Configure router", r)
		enabledRouters[r] = struct{}{}
	}

	for _, router := range availableRouters {
		if _, ok := enabledRouters[router.Name()]; !ok {
			continue
		}

		log.Printf("Add router %q", router.Name())

		h.AddRouter(router)
	}
}
