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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/trillian/monitoring"
)

func TestNoLLRefresher(t *testing.T) {
	llm := NewLogListManager(nil, nil)
	_, err := llm.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("llm.RefreshLogList() on nil LogListRefresher expected to get error, got none")
	}
}

func TestNoLLRefresherAfterRun(t *testing.T) {
	llm := NewLogListManager(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	llm.Run(ctx, 3*time.Second)
	select {
	case <-llm.Errors:
		return
	case <-ctx.Done():
		t.Errorf("llm.Run() on nil LogListRefresher expected to emit error, got none")
	}
}

func TestFirstRefresh(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList3)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList3, err)
	}
	defer func() {
		if err := os.Remove(f); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr := NewLogListRefresher(f)
	llm := NewLogListManager(llr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	llm.Run(ctx, 3*time.Second)
	select {
	case <-llm.LLUpdates:
		return
	case err := <-llm.Errors:
		t.Errorf("llm.Run() emitted error %q while expected none", err)
	case <-ctx.Done():
		t.Errorf("llm.Run() on stub LogListRefresher expected to emit update, got none")
	}
}

// fakeRefresher is a scriptable LogListRefresher for manager-level tests.
type fakeRefresher struct {
	data *LogListData
	err  error
}

func (f *fakeRefresher) Refresh() (*LogListData, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

func (f *fakeRefresher) LastJSON() []byte { return nil }
func (f *fakeRefresher) Source() string   { return "fake" }

// TestManagerKeepsPreviousGenerationOnInvalidData verifies that data which
// slips past a refresher but fails validation is never published, and the last
// good generation stays in place.
func TestManagerKeepsPreviousGenerationOnInvalidData(t *testing.T) {
	good, err := loglist3.NewFromJSON([]byte(testdata.SampleLogList3))
	if err != nil {
		t.Fatalf("NewFromJSON(SampleLogList3) = (_, %v)", err)
	}
	refresher := &fakeRefresher{data: &LogListData{JSON: []byte("good"), List: good}}
	llm := NewLogListManager(refresher, monitoring.InertMetricFactory{})

	first, err := llm.RefreshLogList(context.Background())
	if err != nil {
		t.Fatalf("first RefreshLogList() = (_, %v), want nil", err)
	}

	// A structurally incomplete list that the (fake) refresher failed to
	// reject must still be stopped by the manager.
	bad := &loglist3.LogList{Operators: []*loglist3.Operator{nil}}
	refresher.data = &LogListData{JSON: []byte("bad"), List: bad}
	if _, err := llm.RefreshLogList(context.Background()); err == nil {
		t.Fatalf("RefreshLogList() with invalid list = nil error, want validation error")
	}

	latest, previous := llm.GetTwoLatestLogLists()
	if latest != first {
		t.Errorf("latest generation changed after failed refresh, want first generation retained")
	}
	if previous != nil {
		t.Errorf("previous generation = %v, want nil after single successful refresh", previous)
	}

	// Data without a parsed list is rejected too.
	refresher.data = &LogListData{JSON: []byte("no-list"), List: nil}
	if _, err := llm.RefreshLogList(context.Background()); err == nil {
		t.Fatalf("RefreshLogList() with nil List = nil error, want error")
	}
	if latest, _ := llm.GetTwoLatestLogLists(); latest != first {
		t.Errorf("latest generation changed after nil-List refresh, want retention")
	}
}

// TestManagerPublishesSuccessiveGenerations verifies the normal path: two
// valid refreshes produce latest and previous generations.
func TestManagerPublishesSuccessiveGenerations(t *testing.T) {
	first, err := loglist3.NewFromJSON([]byte(testdata.SampleLogList3))
	if err != nil {
		t.Fatalf("NewFromJSON() = (_, %v)", err)
	}
	secondJSON := strings.Replace(testdata.SampleLogList3, "ct.googleapis.com/racketeer/", "ct.googleapis.com/racketeer/v2/", 1)
	second, err := loglist3.NewFromJSON([]byte(secondJSON))
	if err != nil {
		t.Fatalf("NewFromJSON(updated) = (_, %v)", err)
	}

	refresher := &fakeRefresher{data: &LogListData{JSON: []byte(testdata.SampleLogList3), List: first}}
	llm := NewLogListManager(refresher, monitoring.InertMetricFactory{})

	firstData, err := llm.RefreshLogList(context.Background())
	if err != nil {
		t.Fatalf("first RefreshLogList() = (_, %v)", err)
	}
	refresher.data = &LogListData{JSON: []byte(secondJSON), List: second}
	secondData, err := llm.RefreshLogList(context.Background())
	if err != nil {
		t.Fatalf("second RefreshLogList() = (_, %v)", err)
	}

	latest, previous := llm.GetTwoLatestLogLists()
	if latest != secondData || previous != firstData {
		t.Errorf("generations = (%p, %p), want (%p, %p)", latest, previous, secondData, firstData)
	}
}

func TestSecondRefresh(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList3)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList3, err)
	}
	defer func() {
		if err := os.Remove(f); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr := NewLogListRefresher(f)
	llm := NewLogListManager(llr, monitoring.InertMetricFactory{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	halfCtx, halfCancel := context.WithTimeout(context.Background(), time.Second)
	defer halfCancel()

	llm.Run(ctx, 300*time.Millisecond)
	readFirst := false
First:
	for {
		select {
		case <-llm.LLUpdates:
			if !readFirst {
				readFirst = true
			} else {
				t.Errorf("llm.Run() emitted Log-list update when no updates happened")
			}
		case err := <-llm.Errors:
			t.Errorf("llm.Run() remitted error %q while expected none", err)
		case <-halfCtx.Done():
			if !readFirst {
				t.Errorf("llm.Run() didn't emit any Log-list updates on init. Expected one")
			}
			break First
		}
	}

	sampleLogListUpdate := strings.Replace(testdata.SampleLogList3, "ct.googleapis.com/racketeer/", "ct.googleapis.com/racketeer/v2/", 1)
	if err := os.WriteFile(f, []byte(sampleLogListUpdate), 0644); err != nil {
		t.Fatalf("unable to update Log-list data file: %q", err)
	}
	select {
	case <-llm.LLUpdates:
		return
	case err := <-llm.Errors:
		t.Errorf("llm.Run() emitted error %q while expected none", err)
	case <-ctx.Done():
		t.Errorf("llm.Run() on stub LogListRefresher expected to emit update, got none")
	}
}
