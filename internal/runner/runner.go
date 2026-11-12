package runner

import (
	"fmt"
	"sync"

	"github.com/dwisiswant0/crlfuzz/pkg/crlfuzz"
	"github.com/dwisiswant0/crlfuzz/pkg/errors"
	"github.com/logrusorgru/aurora"
)

// New will fuzz target line by line
func New(options *Options) {
	plan := crlfuzz.BuildPlan(options.Target)
	if len(plan) == 0 {
		errors.Exit("No valid target input provided.")
	}

	jobs := make(chan *crlfuzz.Job)
	results := make(chan *crlfuzz.Result)
	var wg sync.WaitGroup

	workers := options.Concurrency
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results <- options.run(target)
			}
		}()
	}

	go func() {
		for _, job := range plan {
			jobs <- job
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for result := range results {
		options.print(result)
	}
}

func (options *Options) run(job *crlfuzz.Job) *crlfuzz.Result {
	return crlfuzz.ScanJob(
		job,
		options.Method,
		options.Data,
		options.Headers,
		options.Proxy,
	)
}

func (options *Options) print(result *crlfuzz.Result) {
	if result.Status == crlfuzz.StatusVulnerable {
		if options.Silent {
			fmt.Println(crlfuzz.SingleLine(result.URL))
		} else {
			fmt.Printf("[%s] %s %s\n",
				aurora.Green(result.Status.Label()),
				aurora.Bold(result.ID),
				aurora.Green(crlfuzz.SingleLine(result.URL)))
		}

		if options.Output != nil {
			if _, e := options.Output.WriteString(fmt.Sprintf("%s\n", crlfuzz.SingleLine(result.URL))); e != nil {
				errors.Show(e.Error())
			}
		}

		return
	}

	if options.Silent {
		return
	}

	line := fmt.Sprintf("[%s] %s %s", coloredStatus(result.Status), aurora.Bold(result.ID), crlfuzz.SingleLine(result.URL))
	if result.Status == crlfuzz.StatusDuplicate {
		line += fmt.Sprintf(" (duplicate of %s)", aurora.Bold(result.DuplicateOf))
	}
	if options.Verbose && result.Err != nil {
		line += fmt.Sprintf(": %s", result.Err.Error())
	}

	fmt.Println(line)
}

func coloredStatus(status crlfuzz.Status) aurora.Value {
	switch status {
	case crlfuzz.StatusTimeout:
		return aurora.Yellow(status.Label())
	case crlfuzz.StatusError:
		return aurora.Red(status.Label())
	case crlfuzz.StatusDuplicate:
		return aurora.Magenta(status.Label())
	default:
		return aurora.Blue(status.Label())
	}
}
