package crlfuzz

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dwisiswant0/crlfuzz/pkg/request"
)

// RequestTimeout bounds every fuzz request. Tests may override it.
var RequestTimeout = 30 * time.Second

// ScanJob scans a planned Job and returns a Result carrying the same stable
// target identifier and an explicit Status classification, so failures,
// timeouts and clean (non-vulnerable) responses are no longer ambiguous.
func ScanJob(job *Job, method string, data string, headers []string, proxy string) *Result {
	result := &Result{
		ID:          job.ID,
		Source:      job.Source,
		URL:         job.URL,
		DuplicateOf: job.DuplicateOf,
	}

	if job.IsDuplicate() {
		result.Status = StatusDuplicate

		return result
	}

	client := request.Client(proxy, RequestTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	req, e := http.NewRequestWithContext(ctx, method, job.URL, strings.NewReader(data))
	if e != nil {
		result.Status = StatusError
		result.Err = errors.New(e.Error())

		return result
	}
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)

		if len(parts) != 2 {
			continue
		}

		req.Header.Set(parts[0], parts[1])
	}

	res, e := client.Do(req)
	if e != nil {
		result.Err = errors.New(e.Error())
		if isTimeoutError(e) {
			result.Status = StatusTimeout
		} else {
			result.Status = StatusError
		}

		return result
	}
	defer res.Body.Close()

	if isVuln(res) {
		result.Status = StatusVulnerable
	} else {
		result.Status = StatusOK
	}

	return result
}

// Scan will scanning for CRLF vulnerability against target
//
// It is kept as a thin backward-compatible wrapper around ScanJob for users
// embedding crlfuzz as a library.
func Scan(url string, method string, data string, headers []string, proxy string) (bool, error) {
	result := ScanJob(&Job{URL: url}, method, data, headers, proxy)

	return result.Status == StatusVulnerable, result.Err
}

func isVuln(r *http.Response) bool {
	for key, header := range r.Header {
		if key == keyHeader {
			for _, value := range header {
				if strings.Contains(value, valHeader) {
					return true
				}
			}
		}
	}

	return false
}

func isTimeoutError(e error) bool {
	var netErr net.Error
	if errors.As(e, &netErr) && netErr.Timeout() {
		return true
	}

	return errors.Is(e, context.DeadlineExceeded)
}
