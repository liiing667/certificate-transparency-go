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
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	// HttpClientTimeout timeout for Log list reader http client.
	httpClientTimeout = 10 * time.Second
)

// LogListData wraps info on external LogList, keeping its JSON source and time
// of download.
type LogListData struct {
	JSON         []byte
	List         *loglist3.LogList
	DownloadTime time.Time
}

// LogListRefresher is interface for Log List updates watcher.
type LogListRefresher interface {
	Refresh() (*LogListData, error)
	LastJSON() []byte
	Source() string
}

// logListRefresherImpl regularly reads Log-list and emits notifications when
// updates/errors observed. Implements LogListRefresher interface.
type logListRefresherImpl struct {
	// updateMu limits LogListRefresherImpl to a single Refresh() at a time.
	updateMu sync.RWMutex
	lastJSON []byte
	// lastTimestamp is the log_list_timestamp of the last accepted list. It
	// is the zero value for lists that do not carry a timestamp, which keeps
	// older list formats readable.
	lastTimestamp time.Time
	path          string
	client        *http.Client
}

// NewCustomLogListRefresher creates and inits a LogListRefresherImpl instance.
func NewCustomLogListRefresher(client *http.Client, llPath string) LogListRefresher {
	return &logListRefresherImpl{
		path:   llPath,
		client: client,
	}
}

// NewLogListRefresher creates and inits a LogListRefresherImpl instance using
// default http.Client
func NewLogListRefresher(llPath string) LogListRefresher {
	return NewCustomLogListRefresher(&http.Client{Timeout: httpClientTimeout}, llPath)
}

// Refresh fetches the log list and returns its source, formed LogList and
// timestamp if source has changed compared to previous Refresh.
//
// A refresh only produces a new generation when all of the following hold:
//   - the downloaded JSON differs from the last accepted content (an identical
//     re-send is a no-op and creates no new generation);
//   - the JSON parses into a complete, well-formed LogList (truncated or
//     malformed content is rejected);
//   - the list is not older than the last accepted one, as determined by its
//     log_list_timestamp.
//
// On any failure the previously accepted JSON (and therefore the previous
// generation) is preserved.
func (llr *logListRefresherImpl) Refresh() (*LogListData, error) {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()

	t := time.Now()
	jsonData, err := x509util.ReadFileOrURL(llr.path, llr.client)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", llr.path, err)
	}

	// Identical re-send of the current content is not a new generation.
	if bytes.Equal(jsonData, llr.lastJSON) {
		return nil, nil
	}

	ll, err := loglist3.NewFromJSON(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", llr.path, err)
	}
	// Reject structurally incomplete lists before they can reach consumers,
	// where null elements or missing required fields would panic.
	if err := ll.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate %q: %v", llr.path, err)
	}
	// Never move backwards: a downloadable but older list must not replace the
	// current generation. A missing timestamp on either side is treated as
	// unknown, so timestamp-less (older format) lists stay acceptable.
	if !llr.lastTimestamp.IsZero() && !ll.LogListTimestamp.IsZero() && ll.LogListTimestamp.Before(llr.lastTimestamp) {
		return nil, fmt.Errorf("rejected stale log list from %q: timestamp %s is older than current %s",
			llr.path, ll.LogListTimestamp.Format(time.RFC3339), llr.lastTimestamp.Format(time.RFC3339))
	}
	llr.lastJSON = jsonData
	if !ll.LogListTimestamp.IsZero() {
		llr.lastTimestamp = ll.LogListTimestamp
	}
	return &LogListData{JSON: jsonData, List: ll, DownloadTime: t}, nil
}

// LastJSON returns last version of Log list in JSON.
func (llr *logListRefresherImpl) LastJSON() []byte {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()
	if llr.lastJSON == nil {
		return []byte{}
	}
	return llr.lastJSON
}

// Source exposes internal Log list path.
func (llr *logListRefresherImpl) Source() string {
	return llr.path
}
