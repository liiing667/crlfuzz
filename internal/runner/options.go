package runner

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Headers defines custom headers
type Headers []string

func (h Headers) String() string {
	return strings.Join(h, ", ")
}

// Set defines given each header
func (h *Headers) Set(val string) error {
	*h = append(*h, val)
	return nil
}

// Options defines user args
type Options struct {
	URL, List, Method, Data, Proxy, Target, Saveto string
	Concurrency                                    int
	Version, Silent, Verbose                       bool
	Headers                                        Headers
	Output                                         *os.File
}

func newFlagSet() (*flag.FlagSet, *Options) {
	o := &Options{}
	fs := flag.NewFlagSet("crlfuzz", flag.ContinueOnError)

	fs.StringVar(&o.URL, "u", "", "")
	fs.StringVar(&o.URL, "url", "", "")

	fs.StringVar(&o.List, "l", "", "")
	fs.StringVar(&o.List, "list", "", "")

	fs.StringVar(&o.Method, "X", "GET", "")
	fs.StringVar(&o.Method, "method", "GET", "")

	fs.StringVar(&o.Saveto, "o", "", "")
	fs.StringVar(&o.Saveto, "output", "", "")

	fs.StringVar(&o.Data, "d", "", "")
	fs.StringVar(&o.Data, "data", "", "")

	fs.Var(&o.Headers, "header", "")
	fs.Var(&o.Headers, "H", "")

	fs.StringVar(&o.Proxy, "x", "", "")
	fs.StringVar(&o.Proxy, "proxy", "", "")

	fs.IntVar(&o.Concurrency, "c", 25, "")
	fs.IntVar(&o.Concurrency, "concurrent", 25, "")

	fs.BoolVar(&o.Silent, "s", false, "")
	fs.BoolVar(&o.Silent, "silent", false, "")

	fs.BoolVar(&o.Verbose, "v", false, "")
	fs.BoolVar(&o.Verbose, "verbose", false, "")

	fs.BoolVar(&o.Version, "V", false, "")
	fs.BoolVar(&o.Version, "version", false, "")

	// Override help text
	fs.Usage = func() {
		showBanner()
		h := []string{
			"",
			"Usage:" + usage,
			"",
			"Options:" + options,
			"",
		}

		fmt.Fprint(os.Stderr, strings.Join(h, "\n"))
	}

	return fs, o
}

// ParseOptions will parse given args
func ParseOptions() *Options {
	fs, o := newFlagSet()
	if e := fs.Parse(os.Args[1:]); e != nil {
		if e == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Show current version & exit
	if o.Version {
		showVersion()
	}

	// Show banner to user
	if !o.Silent {
		showBanner()
	}

	// Validate input options
	o.validate()

	return o
}
