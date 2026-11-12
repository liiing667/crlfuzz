package crlfuzz

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(keyHeader, valHeader)
		w.WriteHeader(http.StatusOK)
	}))
}

func newSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func newTimeoutServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
}

func withTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()

	original := RequestTimeout
	RequestTimeout = timeout
	t.Cleanup(func() {
		RequestTimeout = original
	})
}

func TestBuildPlanAssignsStableIDsAndSkipsInvalid(t *testing.T) {
	safe := newSafeServer()
	defer safe.Close()

	plan := BuildPlan("\n  \n" + safe.URL + "\nnot-a-url\n" + safe.URL + "/")

	got := map[TargetID]int{}
	for _, job := range plan {
		got[job.ID]++
		if job.ID != "T0001" && job.ID != "T0002" {
			t.Fatalf("unexpected stable target id: %q", job.ID)
		}
	}

	if len(got) != 2 {
		t.Fatalf("expected two stable target ids, got %d: %v", len(got), got)
	}
}

func TestBuildPlanDeduplicatesRepeatedCandidates(t *testing.T) {
	safe := newSafeServer()
	defer safe.Close()

	plan := BuildPlan(safe.URL + "\n" + safe.URL)

	var duplicates, unique int
	for _, job := range plan {
		if job.IsDuplicate() {
			duplicates++
			if job.DuplicateOf != "T0001" {
				t.Fatalf("duplicate must reference first target T0001, got %q", job.DuplicateOf)
			}
		} else {
			unique++
			if job.ID != "T0001" {
				t.Fatalf("only the first target may own unique jobs, got id %q", job.ID)
			}
		}
	}

	if unique == 0 || duplicates != unique {
		t.Fatalf("expected equal unique and duplicate counts, got unique=%d duplicate=%d", unique, duplicates)
	}
}

func TestScanJobClassifiesVulnerable(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	result := ScanJob(&Job{ID: "T0001", URL: server.URL}, "GET", "", nil, "")

	if result.ID != "T0001" {
		t.Fatalf("result lost target id: %q", result.ID)
	}
	if result.Status != StatusVulnerable {
		t.Fatalf("expected %s, got %s", StatusVulnerable, result.Status)
	}
	if result.Err != nil {
		t.Fatalf("vulnerable result must not carry an error: %v", result.Err)
	}
}

func TestScanJobClassifiesSafeAsOK(t *testing.T) {
	server := newSafeServer()
	defer server.Close()

	result := ScanJob(&Job{ID: "T0002", URL: server.URL}, "GET", "", nil, "")

	if result.Status != StatusOK {
		t.Fatalf("expected %s, got %s", StatusOK, result.Status)
	}
	if result.Err != nil {
		t.Fatalf("ok result must not carry an error: %v", result.Err)
	}
}

func TestScanJobClassifiesTimeout(t *testing.T) {
	server := newTimeoutServer()
	defer server.Close()
	withTimeout(t, 25*time.Millisecond)

	start := time.Now()
	result := ScanJob(&Job{ID: "T0003", URL: server.URL}, "GET", "", nil, "")

	if result.Status != StatusTimeout {
		t.Fatalf("expected %s, got %s (err=%v)", StatusTimeout, result.Status, result.Err)
	}
	if result.Err == nil {
		t.Fatal("timeout result must retain the underlying error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout did not abort the request promptly")
	}
}

func TestScanJobClassifiesConnectionFailureAsError(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatalf("listen: %v", e)
	}
	closedURL := "http://" + listener.Addr().String()
	listener.Close()

	result := ScanJob(&Job{ID: "T0004", URL: closedURL}, "GET", "", nil, "")

	if result.Status != StatusError {
		t.Fatalf("expected %s, got %s", StatusError, result.Status)
	}
	if result.Err == nil {
		t.Fatal("connection failure must retain the underlying error")
	}
}

func TestScanJobMarksDuplicateWithoutRequest(t *testing.T) {
	result := ScanJob(&Job{
		ID:          "T0002",
		URL:         "http://127.0.0.1:1/unused",
		DuplicateOf: "T0001",
	}, "GET", "", nil, "")

	if result.Status != StatusDuplicate {
		t.Fatalf("expected %s, got %s", StatusDuplicate, result.Status)
	}
	if result.DuplicateOf != "T0001" {
		t.Fatalf("duplicate reference lost: %q", result.DuplicateOf)
	}
}

func TestLegacyScanRemainsCompatible(t *testing.T) {
	vulnerable := newVulnerableServer()
	defer vulnerable.Close()
	safe := newSafeServer()
	defer safe.Close()

	vuln, err := Scan(vulnerable.URL, "GET", "", nil, "")
	if err != nil || !vuln {
		t.Fatalf("expected vulnerable=true err=nil, got vulnerable=%v err=%v", vuln, err)
	}

	ok, err := Scan(safe.URL, "GET", "", nil, "")
	if err != nil || ok {
		t.Fatalf("expected vulnerable=false err=nil, got vulnerable=%v err=%v", ok, err)
	}

	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatalf("listen: %v", e)
	}
	closedURL := "http://" + listener.Addr().String()
	listener.Close()

	_, err = Scan(closedURL, "GET", "", nil, "")
	if err == nil {
		t.Fatal("expected error for unreachable target")
	}
}

func TestStatusLabelsAreStable(t *testing.T) {
	cases := map[Status]string{
		StatusOK:         "OK",
		StatusVulnerable: "VLN",
		StatusTimeout:    "TIMEOUT",
		StatusError:      "ERROR",
		StatusDuplicate:  "DUP",
	}

	for status, label := range cases {
		if status.Label() != label || status.String() != label {
			t.Fatalf("status %d: expected label %q", status, label)
		}
	}
}

func TestIsValidTarget(t *testing.T) {
	safe := newSafeServer()
	defer safe.Close()

	valid := []string{safe.URL, "http://example.com", "https://example.com/path"}
	for _, raw := range valid {
		if !IsValidTarget(raw) {
			t.Fatalf("expected valid target: %q", raw)
		}
	}

	invalid := []string{"", "   ", "not-a-url", "//example.com", "://missing-scheme"}
	for _, raw := range invalid {
		if IsValidTarget(raw) {
			t.Fatalf("expected invalid target: %q", raw)
		}
	}
}

func TestGenerateURLRemainsStable(t *testing.T) {
	generated := GenerateURL("http://example.com")

	if len(generated) != len(appendList)*len(escapeList) {
		t.Fatalf("expected %d candidates, got %d", len(appendList)*len(escapeList), len(generated))
	}

	seen := map[string]bool{}
	for _, candidate := range generated {
		if seen[candidate] {
			t.Fatalf("generator produced duplicate candidate: %s", candidate)
		}
		seen[candidate] = true
		if !strings.Contains(candidate, keyHeader) || !strings.Contains(candidate, valHeader) {
			t.Fatalf("candidate missing injection markers: %s", candidate)
		}
	}
}
