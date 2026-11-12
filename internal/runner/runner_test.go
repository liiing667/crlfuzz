package runner

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dwisiswant0/crlfuzz/pkg/crlfuzz"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(raw string) string {
	return ansiPattern.ReplaceAllString(raw, "")
}

func newTestServers(t *testing.T) (vulnerable, safe, timedOut *httptest.Server) {
	t.Helper()

	vulnerable = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Injected-Header-By", "CRLFuzz")
		w.WriteHeader(http.StatusOK)
	}))

	safe = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	timedOut = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(func() {
		vulnerable.Close()
		safe.Close()
		timedOut.Close()
	})

	return vulnerable, safe, timedOut
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatalf("pipe: %v", e)
	}
	os.Stdout = write
	buffer := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(read)
		buffer <- string(data)
	}()

	fn()

	_ = write.Close()
	os.Stdout = original

	return <-buffer
}

func TestNewClassifiesEveryTargetWithStableID(t *testing.T) {
	originalTimeout := crlfuzz.RequestTimeout
	crlfuzz.RequestTimeout = 25 * time.Millisecond
	t.Cleanup(func() {
		crlfuzz.RequestTimeout = originalTimeout
	})

	vulnerable, safe, timedOut := newTestServers(t)

	options := &Options{
		Method:      "GET",
		Concurrency: 4,
		Target: strings.Join([]string{
			vulnerable.URL,
			safe.URL,
			timedOut.URL,
			vulnerable.URL,
		}, "\n"),
	}

	output := captureStdout(t, func() {
		New(options)
	})
	output = stripANSI(output)

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("expected per-request classified output")
	}

	counts := map[string]int{}
	ids := map[string]bool{}
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "[VLN]"):
			counts["VLN"]++
		case strings.HasPrefix(line, "[OK]"):
			counts["OK"]++
		case strings.HasPrefix(line, "[ERROR]"):
			counts["ERROR"]++
		case strings.HasPrefix(line, "[TIMEOUT]"):
			counts["TIMEOUT"]++
		case strings.HasPrefix(line, "[DUP]"):
			counts["DUP"]++
		default:
			t.Fatalf("unexpected output line: %q", line)
		}

		if !strings.Contains(line, "T000") {
			t.Fatalf("line missing stable target id: %q", line)
		}

		for _, id := range []string{"T0001", "T0002", "T0003", "T0004"} {
			if strings.Contains(line, id) {
				ids[id] = true
			}
		}
	}

	if len(ids) != 4 {
		t.Fatalf("expected all four target ids in output, got: %v", ids)
	}
	if counts["OK"] == 0 || counts["TIMEOUT"] == 0 || counts["VLN"] == 0 ||
		counts["ERROR"] == 0 || counts["DUP"] == 0 {
		t.Fatalf("expected OK/VLN/TIMEOUT/ERROR/DUP classifications, got: %v", counts)
	}

	candidates := len(crlfuzz.GenerateURL(vulnerable.URL))
	if counts["DUP"] != candidates {
		t.Fatalf("repeated target must yield one duplicate per candidate, expected=%d got=%d",
			candidates, counts["DUP"])
	}

	if !strings.Contains(output, "duplicate of T0001") {
		t.Fatalf("duplicate lines must reference the first target:\n%s", output)
	}
}

func TestNewSilentModeKeepsVulnerableOutputOnly(t *testing.T) {
	vulnerable, safe, _ := newTestServers(t)

	options := &Options{
		Method:      "GET",
		Concurrency: 2,
		Silent:      true,
		Target:      strings.Join([]string{vulnerable.URL, safe.URL}, "\n"),
	}

	output := captureStdout(t, func() {
		New(options)
	})
	output = stripANSI(output)

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, "[") || strings.Contains(line, "T000") {
			t.Fatalf("silent mode must print bare vulnerable URLs only: %q", line)
		}
		if !strings.HasPrefix(line, vulnerable.URL) {
			t.Fatalf("silent mode printed non-vulnerable target: %q", line)
		}
	}

	if strings.TrimSpace(output) == "" {
		t.Fatal("silent mode must still print vulnerable URLs")
	}
}

func TestNewWritesOnlyVulnerableURLsToFile(t *testing.T) {
	vulnerable, safe, timedOut := newTestServers(t)

	file, e := ioutil.TempFile("", "crlfuzz-*.txt")
	if e != nil {
		t.Fatalf("temp file: %v", e)
	}
	name := file.Name()
	_ = file.Close()
	t.Cleanup(func() {
		_ = os.Remove(name)
	})

	output, e := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if e != nil {
		t.Fatalf("open output: %v", e)
	}

	options := &Options{
		Method:      "GET",
		Concurrency: 3,
		Silent:      true,
		Output:      output,
		Target: strings.Join([]string{
			vulnerable.URL,
			safe.URL,
			timedOut.URL,
		}, "\n"),
	}

	New(options)
	_ = output.Close()

	content, e := ioutil.ReadFile(name)
	if e != nil {
		t.Fatalf("read output: %v", e)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("expected vulnerable URLs in output file")
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("output file line must stay single-line: %q", line)
		}
		if !strings.HasPrefix(line, vulnerable.URL) {
			t.Fatalf("output file contains non-vulnerable URL: %q", line)
		}
	}
}
