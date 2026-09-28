package main

import (
	"fmt"
	"os"
	"os/user"
	"runtime"

	"vogt/internal/install"
)

func runInstall(args []string) error {
	fs := newFlags("install", "[--apply] [--user NAME]")
	apply := fs.Bool("apply", false, "carry out the plan (needs root); without it the plan is only printed")
	human := fs.String("user", "", "the account that runs agents and the helper (default: $SUDO_USER or the current user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *human == "" {
		*human = os.Getenv("SUDO_USER")
	}
	if *human == "" {
		if u, err := user.Current(); err == nil {
			*human = u.Username
		}
	}
	steps, err := install.Plan(install.Options{GOOS: runtime.GOOS, HumanUser: *human})
	if err != nil {
		return err
	}
	if !*apply {
		fmt.Println("Installation plan (nothing is changed; rerun with sudo and --apply):")
		for _, s := range steps {
			if s.Desc == "" {
				fmt.Printf("    $ %s\n", s.String()[len("\n    $ "):])
				continue
			}
			fmt.Println("-", s)
		}
		return nil
	}
	return install.Apply(steps)
}
