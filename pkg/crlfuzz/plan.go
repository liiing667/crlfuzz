package crlfuzz

import (
	"fmt"
	"net/url"
	"strings"
)

// Status is the deterministic classification of a single fuzz request.
type Status int

const (
	// StatusOK means the request completed and no CRLF injection was found.
	StatusOK Status = iota
	// StatusVulnerable means the request completed and CRLF injection was confirmed.
	StatusVulnerable
	// StatusTimeout means the request did not complete within RequestTimeout.
	StatusTimeout
	// StatusError means the request failed for any reason other than a timeout.
	StatusError
	// StatusDuplicate means the candidate URL was already planned for an earlier target.
	StatusDuplicate
)

// Label returns the stable, human-readable tag used in CLI output.
func (s Status) Label() string {
	switch s {
	case StatusVulnerable:
		return "VLN"
	case StatusTimeout:
		return "TIMEOUT"
	case StatusError:
		return "ERROR"
	case StatusDuplicate:
		return "DUP"
	default:
		return "OK"
	}
}

// String implements fmt.Stringer.
func (s Status) String() string {
	return s.Label()
}

// TargetID is the stable identifier assigned to a scan target during planning.
// It is shared by the plan, every per-request result and the CLI output.
type TargetID string

func newTargetID(index int) TargetID {
	return TargetID(fmt.Sprintf("T%04d", index))
}

// Job is a single unit of work produced by BuildPlan.
type Job struct {
	// ID identifies the original scan target the candidate belongs to.
	ID TargetID
	// Source is the original target URL supplied by the user.
	Source string
	// URL is the fuzzed candidate URL that will be requested.
	URL string
	// DuplicateOf references the first target planning the same candidate URL.
	// It is empty when the candidate is planned for the first time.
	DuplicateOf TargetID
}

// IsDuplicate reports whether the job was skipped as a duplicate during planning.
func (j *Job) IsDuplicate() bool {
	return j.DuplicateOf != ""
}

// Result is the outcome of scanning a Job. The identifier and classification
// are stable across the planner, the scan layer and the CLI output.
type Result struct {
	ID          TargetID
	Source      string
	URL         string
	Status      Status
	Err         error
	DuplicateOf TargetID
}

// IsValidTarget reports whether the line can be used as a scan target.
func IsValidTarget(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}

	u, e := url.Parse(raw)
	if e != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// SingleLine escapes literal CR/LF characters so a fuzzed URL remains one
// record in terminal output and result files.
func SingleLine(raw string) string {
	replacer := strings.NewReplacer("\r", "\\r", "\n", "\\n")

	return replacer.Replace(raw)
}

// BuildPlan turns the newline-separated targets into an ordered list of jobs.
//
// Every valid target receives a stable, zero-padded TargetID (T0001, T0002,
// ...). Blank lines and invalid targets are skipped. Candidate URLs that were
// already planned for an earlier target are kept as duplicate jobs referencing
// the first target, so the runner never issues the same request twice while
// the duplicate remains visible in the output.
func BuildPlan(rawTargets string) []*Job {
	jobs := make([]*Job, 0)
	seen := make(map[string]TargetID)
	targetNo := 0

	for _, line := range strings.Split(rawTargets, "\n") {
		line = strings.TrimSpace(line)
		if !IsValidTarget(line) {
			continue
		}

		targetNo++
		id := newTargetID(targetNo)

		for _, candidate := range GenerateURL(line) {
			job := &Job{
				ID:     id,
				Source: line,
				URL:    candidate,
			}

			if first, ok := seen[candidate]; ok {
				job.DuplicateOf = first
			} else {
				seen[candidate] = id
			}

			jobs = append(jobs, job)
		}
	}

	return jobs
}
