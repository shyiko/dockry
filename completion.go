package main

import (
	"flag"
	"fmt"
	"github.com/posener/complete"
	"io"
	"os"
	"path/filepath"
)

type Completion struct{}

func (c *Completion) GenBashCompletion(w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "complete -C %s %s\n", bin, filepath.Base(bin))
	return nil
}

func (c *Completion) GenZshCompletion(w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "autoload +X compinit && compinit\nautoload +X bashcompinit && bashcompinit\ncomplete -C %s %s\n",
		bin, filepath.Base(bin))
	return nil
}

func (c *Completion) Execute() (bool, error) {
	bin, err := os.Executable()
	if err != nil {
		return false, err
	}
	platformFlags := map[string]complete.Predictor{
		"--l64":      complete.PredictNothing,
		"-x":         complete.PredictNothing,
		"--platform": complete.PredictAnything,
		"-p":         complete.PredictAnything,
		"--strict":   complete.PredictNothing,
	}
	assign := func(m complete.Flags, tail ...complete.Flags) complete.Flags {
		for _, t := range tail {
			for k, v := range t {
				m[k] = v
			}
		}
		return m
	}
	run := complete.Command{
		Sub: complete.Commands{
			"completion": complete.Command{
				Sub: complete.Commands{
					"bash": complete.Command{},
					"zsh":  complete.Command{},
				},
			},
			"digest": complete.Command{
				Flags: assign(complete.Flags{
					"--fq": complete.PredictNothing,
				}, platformFlags),
				Args: complete.PredictAnything,
			},
			"inspect": complete.Command{
				Flags: assign(complete.Flags{
					"--format": complete.PredictAnything,
				}, platformFlags),
			},
			"ll": complete.Command{
				Flags: assign(complete.Flags{
					"--fq":    complete.PredictNothing,
					"--limit": complete.PredictAnything,
				}, platformFlags),
			},
			"ls": complete.Command{
				Flags: complete.Flags{
					"--fq":    complete.PredictNothing,
					"--limit": complete.PredictAnything,
				},
			},
			"rm": complete.Command{},
			"help": complete.Command{
				Sub: complete.Commands{
					"completion": complete.Command{
						Sub: complete.Commands{
							"bash": complete.Command{},
							"zsh":  complete.Command{},
						},
					},
					"digest":  complete.Command{},
					"inspect": complete.Command{},
					"ll":      complete.Command{},
					"ls":      complete.Command{},
					"rm":      complete.Command{},
				},
			},
		},
		Flags: complete.Flags{
			"--version": complete.PredictNothing,
		},
		GlobalFlags: complete.Flags{
			"--debug": complete.PredictNothing,
			"--user":  complete.PredictAnything,
			"--help":  complete.PredictNothing,
			"-h":      complete.PredictNothing,
		},
	}
	run.Sub["d"] = run.Sub["digest"]
	run.Sub["i"] = run.Sub["inspect"]
	run.Sub["help"].Sub["d"] = run.Sub["help"].Sub["digest"]
	run.Sub["help"].Sub["i"] = run.Sub["help"].Sub["inspect"]
	completion := complete.New(filepath.Base(bin), run)
	if os.Getenv("COMP_LINE") != "" {
		flag.Parse()
		completion.Complete()
		return true, nil
	}
	return false, nil
}

func NewCompletion() *Completion {
	return &Completion{}
}
