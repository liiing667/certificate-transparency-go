// Copyright 2026 Google LLC. All Rights Reserved.
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

package loglist3

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func validLog() *Log {
	return &Log{
		Description: "valid log",
		LogID:       make([]byte, sha256.Size),
		Key:         []byte{0x01, 0x02, 0x03},
		URL:         "https://ct.example.com/log/",
		MMD:         86400,
	}
}

func validTiledLog() *TiledLog {
	return &TiledLog{
		Description:   "valid tiled log",
		LogID:         make([]byte, sha256.Size),
		Key:           []byte{0x01, 0x02, 0x03},
		SubmissionURL: "https://ct.example.com/log/submit/",
		MonitoringURL: "https://ct.example.com/log/monitor/",
		MMD:           86400,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*LogList)
		wantErrSubs string
	}{
		{
			name:   "Valid",
			modify: func(ll *LogList) {},
		},
		{
			name:   "EmptyOperatorsIsValid",
			modify: func(ll *LogList) { ll.Operators = nil },
		},
		{
			name:   "MissingTimestampIsValid",
			modify: func(ll *LogList) { ll.LogListTimestamp = time.Time{} },
		},
		{
			name:        "NullOperator",
			modify:      func(ll *LogList) { ll.Operators = append(ll.Operators, nil) },
			wantErrSubs: "is null",
		},
		{
			name:        "OperatorWithoutName",
			modify:      func(ll *LogList) { ll.Operators[0].Name = "" },
			wantErrSubs: "has no name",
		},
		{
			name:        "NullLog",
			modify:      func(ll *LogList) { ll.Operators[0].Logs = append(ll.Operators[0].Logs, nil) },
			wantErrSubs: "is null",
		},
		{
			name:        "LogMissingDescription",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].Description = "" },
			wantErrSubs: "missing description",
		},
		{
			name:        "LogMissingLogID",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].LogID = nil },
			wantErrSubs: "invalid log_id length",
		},
		{
			name:        "LogWrongLogIDLength",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].LogID = []byte{0x01} },
			wantErrSubs: "invalid log_id length",
		},
		{
			name:        "LogMissingKey",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].Key = nil },
			wantErrSubs: "missing public key",
		},
		{
			name:        "LogMissingURL",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].URL = "" },
			wantErrSubs: "missing url",
		},
		{
			name:        "LogZeroMMD",
			modify:      func(ll *LogList) { ll.Operators[0].Logs[0].MMD = 0 },
			wantErrSubs: "invalid mmd",
		},
		{
			name:        "NullTiledLog",
			modify:      func(ll *LogList) { ll.Operators[0].TiledLogs = append(ll.Operators[0].TiledLogs, nil) },
			wantErrSubs: "is null",
		},
		{
			name: "TiledLogMissingSubmissionURL",
			modify: func(ll *LogList) {
				ll.Operators[0].TiledLogs = append(ll.Operators[0].TiledLogs, validTiledLog())
				ll.Operators[0].TiledLogs[0].SubmissionURL = ""
			},
			wantErrSubs: "missing submission_url",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ll := &LogList{
				Operators: []*Operator{{
					Name: "Operator",
					Logs: []*Log{validLog()},
				}},
			}
			tc.modify(ll)
			err := ll.Validate()
			if tc.wantErrSubs == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErrSubs)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubs) {
				t.Fatalf("Validate() = %q, want error containing %q", err.Error(), tc.wantErrSubs)
			}
		})
	}
}

func TestValidateNilLogList(t *testing.T) {
	var ll *LogList
	if err := ll.Validate(); err == nil {
		t.Fatalf("nil LogList.Validate() = nil, want error")
	}
}

// TestValidateRejectsNullJSONElement reproduces the crash where a null array
// element parsed without error but panicked later inside SelectByStatus.
func TestValidateRejectsNullJSONElement(t *testing.T) {
	jsonData := []byte(`{"operators":[null,{"name":"Google","logs":[]}]}`)
	ll, err := NewFromJSON(jsonData)
	if err != nil {
		t.Fatalf("NewFromJSON() = %v, want nil", err)
	}
	if err := ll.Validate(); err == nil {
		t.Fatalf("Validate() accepted list with null operator, want error")
	}
}
