// Copyright 2019 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package submission

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/go-cmp/cmp"
)

// createTempFile creates a file in the system's temp directory and writes data to it.
// It returns the name of the file.
func createTempFile(data string) (string, error) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("Operation to close file failed: %v", err)
		}
	}()
	if _, err := f.WriteString(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func ExampleLogListRefresher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f, err := createTempFile(`{"operators": [{"name":"Google"}]}`)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Remove(f); err != nil {
			log.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr := NewLogListRefresher(f)

	// Refresh log list periodically so it stays up-to-date.
	// Not necessary for this example, but appropriate for long-running systems.
	llChan := make(chan *LogListData)
	errChan := make(chan error)
	go schedule.Every(ctx, time.Hour, func(ctx context.Context) {
		if ll, err := llr.Refresh(); err != nil {
			errChan <- err
		} else {
			llChan <- ll
		}
	})

	select {
	case ll := <-llChan:
		fmt.Printf("# Log Operators: %d\n", len(ll.List.Operators))
	case err := <-errChan:
		panic(err)
	case <-ctx.Done():
		panic("Context expired")
	}
	// Output:
	// # Log Operators: 1
}

func TestNewLogListRefresherNoFile(t *testing.T) {
	const wantErrSubstr = "failed to read"
	llr := NewLogListRefresher("nofile.json")
	if _, err := llr.Refresh(); !strings.Contains(err.Error(), wantErrSubstr) {
		t.Errorf("llr.Refresh() = (_, %v), want err containing %q", err, wantErrSubstr)
	}
}

type fakeTransport struct {
	called bool
}

func (ft *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.called = true
	return nil, fmt.Errorf("fakeTransport got called")
}

func TestNewCustomLogListRefresher(t *testing.T) {
	transport := fakeTransport{}
	client := &http.Client{Transport: &transport, Timeout: time.Second}

	llr := NewCustomLogListRefresher(client, "https://loglist.net/")
	if _, err := llr.Refresh(); err == nil {
		t.Errorf("Expected llr.Refresh() to return error using fakeTransport, got none")
	}
	if transport.called != true {
		t.Errorf("NewCustomLogListRefresher initialized with fakeTransport didn't call it on Refresh()")
	}
}

func TestNewLogListRefresher(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		wantLl    *loglist3.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:   "SuccessfulRead",
			ll:     `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl: &loglist3.LogList{Operators: []*loglist3.Operator{{Name: "Google"}}},
		},
		{
			name:      "CannotParseInput",
			ll:        `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer func() {
				if err := os.Remove(f); err != nil {
					t.Fatalf("Operation to remove temp file failed: %v", err)
				}
			}()

			beforeRefresh := time.Now()
			llr := NewLogListRefresher(f)
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if (ll == nil) != (tc.wantLl == nil) {
				t.Fatalf("llr.Refresh() = (%v, _), expected value? %t", ll, tc.wantLl != nil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(ll.List, tc.wantLl); diff != "" {
				t.Errorf("llr.Refresh() LogList: diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.ll)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}

// validRefresherLogList builds a minimal but complete v3 log list with the
// given log_list_timestamp.
func validRefresherLogList(timestamp string) string {
	ts := ""
	if timestamp != "" {
		ts = fmt.Sprintf(`"log_list_timestamp":%q,`, timestamp)
	}
	return fmt.Sprintf(`{%s"operators":[{"name":"Google","logs":[
		{"description":"Google 'Aviator' log",
		 "log_id":"aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",
		 "key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==",
		 "url":"https://ct.googleapis.com/aviator/",
		 "mmd":86400,
		 "state":{"usable":{"timestamp":"2018-02-27T00:00:00Z"}}}]}]}`, ts)
}

// writeRefreshFile replaces the contents of the temp file used by a refresher.
func writeRefreshFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) = %v, want nil", path, err)
	}
}

// TestRefreshRejectsIncompleteList ensures a list that parses but contains
// truncated objects is rejected and does not replace the previous generation.
func TestRefreshRejectsIncompleteList(t *testing.T) {
	good := validRefresherLogList("2024-01-01T00:00:00Z")
	f, err := createTempFile(good)
	if err != nil {
		t.Fatalf("createTempFile() = (_, %v)", err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	first, err := llr.Refresh()
	if err != nil {
		t.Fatalf("first Refresh() = (_, %v), want nil error", err)
	}
	if first == nil {
		t.Fatalf("first Refresh() = nil data, want first generation")
	}

	// A null operator parses fine but is structurally incomplete.
	writeRefreshFile(t, f, `{"log_list_timestamp":"2024-02-01T00:00:00Z","operators":[null]}`)
	if lld, err := llr.Refresh(); err == nil {
		t.Fatalf("Refresh() with null operator = (%v, nil), want validation error", lld)
	}

	// The previous generation must be untouched.
	if got, want := string(llr.LastJSON()), good; got != want {
		t.Errorf("LastJSON() after failed refresh = %q, want previous generation %q", got, want)
	}

	// A log missing required fields is likewise rejected.
	writeRefreshFile(t, f, `{"log_list_timestamp":"2024-02-01T00:00:00Z","operators":[{"name":"Google","logs":[{"description":"broken"}]}]}`)
	if lld, err := llr.Refresh(); err == nil {
		t.Fatalf("Refresh() with truncated log = (%v, nil), want validation error", lld)
	}
	if got := string(llr.LastJSON()); got != good {
		t.Errorf("LastJSON() after second failed refresh = %q, want %q", got, good)
	}
}

// TestRefreshRejectsOlderGeneration ensures an older but still parseable list
// cannot overwrite the current generation.
func TestRefreshRejectsOlderGeneration(t *testing.T) {
	newer := validRefresherLogList("2024-03-01T00:00:00Z")
	f, err := createTempFile(newer)
	if err != nil {
		t.Fatalf("createTempFile() = (_, %v)", err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	if _, err := llr.Refresh(); err != nil {
		t.Fatalf("first Refresh() = (_, %v), want nil error", err)
	}

	older := validRefresherLogList("2024-01-01T00:00:00Z")
	writeRefreshFile(t, f, older)
	lld, err := llr.Refresh()
	if err == nil {
		t.Fatalf("Refresh() with older list = (%v, nil), want stale-list error", lld)
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("Refresh() error = %q, want message containing %q", err.Error(), "stale")
	}
	if got := string(llr.LastJSON()); got != newer {
		t.Errorf("LastJSON() after stale refresh = %q, want current generation preserved", got)
	}

	// An equal-or-newer timestamp with different content is accepted.
	equal := validRefresherLogList("2024-03-01T00:00:00Z")
	equal = strings.Replace(equal, "aviator", "aviator2", 1)
	writeRefreshFile(t, f, equal)
	lld, err = llr.Refresh()
	if err != nil {
		t.Fatalf("Refresh() with equal timestamp = (_, %v), want acceptance", err)
	}
	if lld == nil {
		t.Fatalf("Refresh() with equal timestamp returned no data, want new generation")
	}
}

// TestRefreshSameContentNoNewGeneration ensures re-sending identical bytes is
// a no-op even after intervening failed refreshes.
func TestRefreshSameContentNoNewGeneration(t *testing.T) {
	good := validRefresherLogList("2024-01-01T00:00:00Z")
	f, err := createTempFile(good)
	if err != nil {
		t.Fatalf("createTempFile() = (_, %v)", err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	if _, err := llr.Refresh(); err != nil {
		t.Fatalf("first Refresh() = (_, %v), want nil error", err)
	}

	// Identical content again creates no generation.
	lld, err := llr.Refresh()
	if err != nil {
		t.Fatalf("Refresh() identical content = (_, %v), want nil error", err)
	}
	if lld != nil {
		t.Fatalf("Refresh() identical content = %v, want nil (no new generation)", lld)
	}

	// A failed refresh must not make the same content look like an update.
	writeRefreshFile(t, f, `not json at all`)
	if _, err := llr.Refresh(); err == nil {
		t.Fatalf("Refresh() with garbage = nil error, want parse error")
	}
	writeRefreshFile(t, f, good)
	lld, err = llr.Refresh()
	if err != nil {
		t.Fatalf("Refresh() restoring identical content = (_, %v), want nil error", err)
	}
	if lld != nil {
		t.Fatalf("Refresh() restoring identical content = %v, want nil (no new generation)", lld)
	}
}

// TestRefreshOlderFormatWithoutTimestamp ensures lists without a
// log_list_timestamp remain readable and do not trigger rollback rejection.
func TestRefreshOlderFormatWithoutTimestamp(t *testing.T) {
	oldFormat := validRefresherLogList("")
	f, err := createTempFile(oldFormat)
	if err != nil {
		t.Fatalf("createTempFile() = (_, %v)", err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	lld, err := llr.Refresh()
	if err != nil {
		t.Fatalf("Refresh() timestamp-less list = (_, %v), want acceptance", err)
	}
	if lld == nil {
		t.Fatalf("Refresh() timestamp-less list returned no data, want first generation")
	}

	// A second, different but still timestamp-less list is accepted: unknown
	// timestamps must not be treated as a rollback.
	oldFormat2 := strings.Replace(oldFormat, "aviator", "aviator2", 1)
	writeRefreshFile(t, f, oldFormat2)
	lld, err = llr.Refresh()
	if err != nil {
		t.Fatalf("Refresh() second timestamp-less list = (_, %v), want acceptance", err)
	}
	if lld == nil {
		t.Fatalf("Refresh() second timestamp-less list returned no data, want new generation")
	}

	// And a timestamped list following timestamp-less ones is accepted too.
	writeRefreshFile(t, f, validRefresherLogList("2024-01-01T00:00:00Z"))
	if _, err := llr.Refresh(); err != nil {
		t.Fatalf("Refresh() timestamped list after legacy = (_, %v), want acceptance", err)
	}
}

func TestNewLogListRefresherUpdate(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		llNext    string
		wantLl    *loglist3.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:      "NoUpdate",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl:    nil,
			errRegexp: nil,
		},
		{
			name:      "LogListUpdated",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"GoogleOps"}]}`,
			wantLl:    &loglist3.LogList{Operators: []*loglist3.Operator{{Name: "GoogleOps"}}},
			errRegexp: nil,
		},
		{
			name:      "CannotParseInput",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer func() {
				if err := os.Remove(f); err != nil {
					t.Fatalf("Operation to remove temp file failed: %v", err)
				}
			}()

			llr := NewLogListRefresher(f)
			if _, err := llr.Refresh(); err != nil {
				t.Fatalf("llr.Refresh() = (_, %v), want (_, nil)", err)
			}

			// Simulate Log list update.
			if err := os.WriteFile(f, []byte(tc.llNext), 0755); err != nil {
				t.Fatalf("os.WriteFile(%q, %q) = %q, want nil", f, tc.llNext, err)
			}

			beforeRefresh := time.Now()
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if llNil, wantNil := ll == nil, tc.wantLl == nil; llNil != wantNil {
				t.Fatalf("llr.Refresh() = (%v, _), expected nil? %t", ll, wantNil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(tc.wantLl, ll.List); diff != "" {
				t.Errorf("llr.Refresh(): diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.llNext)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}
