// Copyright 2016 Google LLC. All Rights Reserved.
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

package jsonclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/testdata"
)

func publicKeyPEMToDER(key string) []byte {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		panic("failed to decode public key PEM")
	}
	if block.Type != "PUBLIC KEY" {
		panic("PEM does not have type 'PUBLIC KEY'")
	}
	return block.Bytes
}

func TestNewJSONClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "invalid PublicKey",
			opts:    Options{PublicKey: "bogus"},
			wantErr: "no PEM block",
		},
		{
			name:    "invalid PublicKeyDER",
			opts:    Options{PublicKeyDER: []byte("bogus")},
			wantErr: "asn1: structure error",
		},
		{
			name: "RSA PublicKey",
			opts: Options{PublicKey: testdata.RsaPublicKeyPEM},
		},
		{
			name: "RSA PublicKeyDER",
			opts: Options{PublicKeyDER: publicKeyPEMToDER(testdata.RsaPublicKeyPEM)},
		},
		{
			name: "ECDSA PublicKey",
			opts: Options{PublicKey: testdata.EcdsaPublicKeyPEM},
		},
		{
			name: "ECDSA PublicKeyDER",
			opts: Options{PublicKeyDER: publicKeyPEMToDER(testdata.EcdsaPublicKeyPEM)},
		},
		{
			name:    "DSA PublicKey",
			opts:    Options{PublicKey: testdata.DsaPublicKeyPEM},
			wantErr: "unsupported public key type",
		},
		{
			name:    "DSA PublicKeyDER",
			opts:    Options{PublicKeyDER: publicKeyPEMToDER(testdata.DsaPublicKeyPEM)},
			wantErr: "unsupported public key type",
		},
		{
			name:    "PublicKey contains trailing garbage",
			opts:    Options{PublicKey: testdata.RsaPublicKeyPEM + "bogus"},
			wantErr: "extra data found",
		},
		{
			name:    "PublicKeyDER contains trailing garbage",
			opts:    Options{PublicKeyDER: append(publicKeyPEMToDER(testdata.RsaPublicKeyPEM), []byte("deadbeef")...)},
			wantErr: "trailing data",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := New("http://127.0.0.1", nil, test.opts)
			if err != nil {
				if len(test.wantErr) == 0 {
					t.Errorf("New()=nil,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("New()=nil,%v; want _, error containing %q", err, test.wantErr)
				}
				return
			}
			if len(test.wantErr) > 0 {
				t.Errorf("New()=_,nil; want nil, error containing %q", test.wantErr)
			}
			if got == nil {
				t.Errorf("New()=nil,nil; want non-nil,nil")
			}
		})
	}
}

type TestStruct struct {
	TreeSize  int    `json:"tree_size"`
	Timestamp int    `json:"timestamp"`
	Data      string `json:"data"`
}

type TestParams struct {
	RespCode int `json:"rc"`
}

func MockServer(t *testing.T, failCount int, retryAfter int) *httptest.Server {
	t.Helper()
	mu := sync.Mutex{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/struct/path":
			if _, err := fmt.Fprintf(w, `{"tree_size": 11, "timestamp": 99}`); err != nil {
				t.Errorf("Failed to fmt.Fprintf: %v", err)
			}
		case "/struct/params":
			var s TestStruct
			if r.Method == http.MethodGet {
				s.TreeSize, _ = strconv.Atoi(r.FormValue("tree_size"))
				s.Timestamp, _ = strconv.Atoi(r.FormValue("timestamp"))
				s.Data = r.FormValue("data")
			} else {
				decoder := json.NewDecoder(r.Body)
				err := decoder.Decode(&s)
				if err != nil {
					t.Fatalf("Failed to decode: %v", err)
				}
				defer func() {
					if err := r.Body.Close(); err != nil {
						t.Fatalf("Failed to close request body: %v", err)
					}
				}()
			}
			if _, err := fmt.Fprintf(w, `{"tree_size": %d, "timestamp": %d, "data": "%s"}`, s.TreeSize, s.Timestamp, s.Data); err != nil {
				t.Errorf("Failed to fmt.Fprintf: %v", err)
			}
		case "/error":
			var params TestParams
			if r.Method == http.MethodGet {
				params.RespCode, _ = strconv.Atoi(r.FormValue("rc"))
			} else {
				decoder := json.NewDecoder(r.Body)
				err := decoder.Decode(&params)
				if err != nil {
					t.Fatalf("Failed to decode: %v", err)
				}
				defer func() {
					if err := r.Body.Close(); err != nil {
						t.Fatalf("Failed to close request body: %v", err)
					}
				}()
			}
			http.Error(w, "error page", params.RespCode)
		case "/malformed":
			// no closing }
			if _, err := fmt.Fprintf(w, `{"tree_size": 11, "timestamp": 99`); err != nil {
				t.Errorf("Failed to fmt.Fprintf: %v", err)
			}
		case "/retry":
			if failCount > 0 {
				failCount--
				if retryAfter != 0 {
					if retryAfter > 0 {
						w.Header().Add("Retry-After", strconv.Itoa(retryAfter))
					}
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					w.WriteHeader(http.StatusRequestTimeout)
				}
			} else {
				if _, err := fmt.Fprintf(w, `{"tree_size": 11, "timestamp": 99}`); err != nil {
					t.Errorf("Failed to fmt.Fprintf: %v", err)
				}
			}
		case "/retry-rfc1123":
			if failCount > 0 {
				failCount--
				w.Header().Add("Retry-After", time.Now().Add(time.Duration(retryAfter)*time.Second).Format(time.RFC1123))
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				if _, err := fmt.Fprintf(w, `{"tree_size": 11, "timestamp": 99}`); err != nil {
					t.Errorf("Failed to fmt.Fprintf: %v", err)
				}
			}
		case "/useragent/banana":
			if got, want := r.Header.Get("User-Agent"), "banana"; got != want {
				w.WriteHeader(400)
			}
			if _, err := fmt.Fprintf(w, `{}`); err != nil {
				t.Errorf("Failed to fmt.Fprintf: %v", err)
			}
		case "/useragent/none":
			if got, want := r.Header.Get("User-Agent"), ""; got != want {
				w.WriteHeader(400)
			}
			if _, err := fmt.Fprintf(w, `{}`); err != nil {
				t.Errorf("Failed to fmt.Fprintf: %v", err)
			}
		default:
			t.Fatalf("Unhandled URL path: %s", r.URL.Path)
		}
	}))
}

func TestGetAndParse(t *testing.T) {
	tests := []struct {
		uri        string
		params     map[string]string
		wantStatus int
		want       TestStruct
		wantErr    string
		ua         string
	}{
		{uri: "/short%", wantErr: "invalid URL escape"},
		{uri: "/malformed", wantStatus: http.StatusOK, wantErr: "unexpected EOF"},
		{uri: "/error", params: map[string]string{"rc": "404"}, wantErr: "404 Not Found"},
		{uri: "/error", params: map[string]string{"rc": "403"}, wantErr: "403 Forbidden"},
		{uri: "/struct/path", wantStatus: http.StatusOK, want: TestStruct{11, 99, ""}},
		{uri: "/useragent/banana", wantStatus: http.StatusOK, ua: "banana"},
		{uri: "/useragent/banana", wantErr: "400 Bad Request", ua: "not-a-banana"},
		{
			uri:        "/struct/params",
			params:     map[string]string{"tree_size": "42", "timestamp": "88", "data": "abcd"},
			wantStatus: http.StatusOK,
			want:       TestStruct{42, 88, "abcd"},
		},
	}

	ts := MockServer(t, -1, 0)
	defer ts.Close()

	ctx := context.Background()

	for _, test := range tests {
		logClient, err := New(ts.URL, &http.Client{}, Options{UserAgent: test.ua})
		if err != nil {
			t.Fatal(err)
		}
		var got TestStruct
		httpRsp, body, err := logClient.GetAndParse(ctx, test.uri, test.params, &got)
		var gotStatus int
		if httpRsp != nil {
			gotStatus = httpRsp.StatusCode
		} else if rspErr, ok := err.(RspError); ok {
			gotStatus = rspErr.StatusCode
		}

		if err != nil {
			if len(test.wantErr) == 0 {
				t.Errorf("GetAndParse(%q)=_,_,%q; want _, _, nil", test.uri, err.Error())
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("GetAndParse(%q)=_,_,%q; want _, _, error containing %q", test.uri, err.Error(), test.wantErr)
			}
			continue
		}

		if len(test.wantErr) > 0 {
			t.Errorf("GetAndParse(%q)=%+v,_,nil; want error matching %q", test.uri, got, test.wantErr)
		}
		if gotStatus != test.wantStatus {
			t.Errorf("GetAndParse('%s') got status %d; want %d", test.uri, gotStatus, test.wantStatus)
		}

		if body == nil {
			t.Errorf("GetAndParse(%q)=_,nil,_; want _,non-nil,_", test.uri)
		}
		if test.wantStatus == http.StatusOK {
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("GetAndParse(%q)=%+v,_,nil; want %+v", test.uri, got, test.want)
			}
		}
	}
}

func TestPostAndParse(t *testing.T) {
	tests := []struct {
		uri        string
		request    interface{}
		wantStatus int
		want       TestStruct
		wantErr    bool
		ua         string
	}{
		{uri: "/short%", wantErr: true},
		{uri: "/struct/params", request: json.Number(`invalid`), wantErr: true},
		{uri: "/malformed", wantStatus: http.StatusOK, wantErr: true},
		{uri: "/error", request: TestParams{RespCode: 404}, wantStatus: http.StatusNotFound},
		{uri: "/error", request: TestParams{RespCode: 403}, wantStatus: http.StatusForbidden},
		{uri: "/struct/path", wantStatus: http.StatusOK, want: TestStruct{11, 99, ""}},
		{uri: "/useragent/banana", wantStatus: http.StatusOK, ua: "banana"},
		{uri: "/useragent/banana", wantStatus: 400, ua: "not-a-banana"},
		{
			uri:        "/struct/params",
			wantStatus: http.StatusOK,
			request:    TestStruct{42, 88, "abcd"},
			want:       TestStruct{42, 88, "abcd"},
		},
	}

	ts := MockServer(t, -1, 0)
	defer ts.Close()

	ctx := context.Background()

	for _, test := range tests {
		logClient, err := New(ts.URL, &http.Client{}, Options{UserAgent: test.ua})
		if err != nil {
			t.Fatal(err)
		}
		var got TestStruct
		httpRsp, body, err := logClient.PostAndParse(ctx, test.uri, test.request, &got)
		var gotStatus int
		if httpRsp != nil {
			gotStatus = httpRsp.StatusCode
		} else if rspErr, ok := err.(RspError); ok {
			gotStatus = rspErr.StatusCode
		}

		if err != nil {
			if !test.wantErr {
				t.Errorf("PostAndParse(%q)=_,_,%q; want _, _, nil", test.uri, err.Error())
			}
			continue
		}

		if test.wantErr {
			t.Errorf("PostAndParse(%q)=%+v,nil; want error", test.uri, got)
		}
		if gotStatus != test.wantStatus {
			t.Errorf("PostAndParse('%s') got status %d; want %d", test.uri, gotStatus, test.wantStatus)
		}
		if body == nil {
			t.Errorf("PostAndParse(%q)=_,nil,_; want _,non-nil,_ ", test.uri)
		}
		if test.wantStatus == http.StatusOK {
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("PostAndParse(%q)=%+v,nil; want %+v", test.uri, got, test.want)
			}
		}
	}
}

// mockBackoff is not safe for concurrent usage
type mockBackoff struct {
	override time.Duration
}

func (mb *mockBackoff) set(o *time.Duration) time.Duration {
	if o != nil {
		mb.override = *o
	}
	return 0
}
func (mb *mockBackoff) decreaseMultiplier() {}
func (mb *mockBackoff) until() time.Time    { return time.Time{} }

func TestPostAndParseWithRetry(t *testing.T) {
	tests := []struct {
		uri             string
		request         interface{}
		deadlineSecs    int // -1 indicates no deadline
		retryAfter      int // -1 indicates generate 503 with no Retry-After
		failCount       int
		wantErr         string
		expectedBackoff time.Duration // 0 indicates no expected backoff override set
		leeway          time.Duration
	}{
		{
			uri:             "/error",
			request:         TestParams{RespCode: 418},
			deadlineSecs:    -1,
			retryAfter:      0,
			failCount:       0,
			wantErr:         "teapot",
			expectedBackoff: 0,
		},
		{
			uri:             "/short%",
			request:         nil,
			deadlineSecs:    0,
			retryAfter:      0,
			failCount:       0,
			wantErr:         "deadline exceeded",
			expectedBackoff: 0,
		},
		{
			uri:             "/retry",
			request:         nil,
			deadlineSecs:    -1,
			retryAfter:      0,
			failCount:       1,
			wantErr:         "",
			expectedBackoff: 0,
		},
		{
			uri:             "/retry",
			request:         nil,
			deadlineSecs:    -1,
			retryAfter:      5,
			failCount:       1,
			wantErr:         "",
			expectedBackoff: 5 * time.Second,
		},
		{
			uri:             "/retry-rfc1123",
			request:         nil,
			deadlineSecs:    -1,
			retryAfter:      5,
			failCount:       1,
			wantErr:         "",
			expectedBackoff: 5 * time.Second,
			leeway:          2 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.uri, func(t *testing.T) {
			ts := MockServer(t, test.failCount, test.retryAfter)
			defer ts.Close()

			logClient, err := New(ts.URL, &http.Client{}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			mb := mockBackoff{}
			logClient.backoff = &mb
			ctx := context.Background()
			if test.deadlineSecs >= 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Duration(test.deadlineSecs)*time.Second))
				defer cancel()
			}

			var got TestStruct
			httpRsp, _, err := logClient.PostAndParseWithRetry(ctx, test.uri, test.request, &got)
			if test.wantErr != "" {
				if err == nil {
					t.Errorf("PostAndParseWithRetry()=%+v,nil; want error %q", got, test.wantErr)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("PostAndParseWithRetry()=nil,%q; want error %q", err.Error(), test.wantErr)
				} else if _, isRspError := err.(RspError); !isRspError && err != context.DeadlineExceeded {
					// We expect all non-nil errors to be either a RspError instance or to
					// be the context DeadlineExceeded error.
					t.Errorf("PostAndParseWithRetry()=%T; want jsonClient.RspError or context.DeadlineExceeded", err)
				}
				return
			}
			if err != nil {
				t.Errorf("PostAndParseWithRetry()=nil,%q; want no error", err.Error())
			} else if httpRsp.StatusCode != http.StatusOK {
				t.Errorf("PostAndParseWithRetry() got status %d; want OK(404)", httpRsp.StatusCode)
			}
			leeway := test.leeway
			if leeway == 0 {
				leeway = time.Second
			}
			if test.expectedBackoff > 0 && !fuzzyDurationEquals(test.expectedBackoff, mb.override, leeway) {
				t.Errorf("Unexpected backoff override set: got: %s, wanted: %s", mb.override, test.expectedBackoff)
			}
		})
	}
}

// nolint:staticcheck
func TestContextRequired(t *testing.T) {
	ts := MockServer(t, -1, 0)
	defer ts.Close()

	logClient, err := New(ts.URL, &http.Client{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var result TestStruct
	_, _, err = logClient.GetAndParse(nil, "/struct/path", nil, &result)
	if err == nil {
		t.Errorf("GetAndParse() succeeded with empty Context")
	}
	_, _, err = logClient.PostAndParse(nil, "/struct/path", nil, &result)
	if err == nil {
		t.Errorf("PostAndParse() succeeded with empty Context")
	}
	_, _, err = logClient.PostAndParseWithRetry(nil, "/struct/path", nil, &result)
	if err == nil {
		t.Errorf("PostAndParseWithRetry() succeeded with empty Context")
	}
}

func TestCancelledContext(t *testing.T) {
	ts := MockServer(t, -1, 0)
	defer ts.Close()
	logClient, err := New(ts.URL, &http.Client{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var result TestStruct
	_, _, err = logClient.GetAndParse(ctx, "/struct/path", nil, &result)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("GetAndParse() = (_,_,%v), want %q", err, context.Canceled)
	}
	_, _, err = logClient.PostAndParse(ctx, "/struct/path", nil, &result)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("PostAndParse() = (_,_,%v), want %q", err, context.Canceled)
	}
	_, _, err = logClient.PostAndParseWithRetry(ctx, "/struct/path", nil, &result)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("PostAndParseWithRetry() = (_,_,%v), want %q", err, context.Canceled)
	}
}

func TestSameAuthority(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "identical", a: "http://example.com/ct/v1/get-sth", b: "http://example.com/ct/v1/get-roots", want: true},
		{name: "default http port", a: "http://example.com:80/x", b: "http://example.com/y", want: true},
		{name: "default https port", a: "https://example.com:443/x", b: "https://example.com/y", want: true},
		{name: "case-insensitive host", a: "http://Example.COM/x", b: "http://example.com/y", want: true},
		{name: "different port", a: "http://example.com:8080/x", b: "http://example.com:9090/y", want: false},
		{name: "explicit port vs default port", a: "http://example.com:80/x", b: "http://example.com:8080/y", want: false},
		{name: "different scheme", a: "http://example.com/x", b: "https://example.com/y", want: false},
		{name: "different host", a: "http://a.example.com/x", b: "http://b.example.com/y", want: false},
		{name: "subdomain is different", a: "http://example.com/x", b: "http://sub.example.com/y", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, err := url.Parse(test.a)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", test.a, err)
			}
			b, err := url.Parse(test.b)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", test.b, err)
			}
			if got := sameAuthority(a, b); got != test.want {
				t.Errorf("sameAuthority(%q, %q) = %v, want %v", test.a, test.b, got, test.want)
			}
		})
	}
}

// scriptedRoundTripper returns canned responses without performing any real
// network I/O, and records every request (including redirect follow-ups) so
// that header handling can be inspected.
type scriptedRoundTripper struct {
	mu       sync.Mutex
	rsps     []*http.Response
	errs     []error
	requests []*http.Request
}

func (s *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := len(s.requests)
	s.requests = append(s.requests, req)
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	if i >= len(s.rsps) {
		return nil, fmt.Errorf("scriptedRoundTripper: no scripted response for request %d to %q", i, req.URL)
	}
	rsp := s.rsps[i]
	if rsp.Header == nil {
		rsp.Header = http.Header{}
	}
	rsp.Request = req
	return rsp, nil
}

func newResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// TestGetAndParseStrictJSON makes sure that only a response body containing a
// single complete JSON value is accepted; a valid JSON object followed by
// trailing data must not be treated as success.
func TestGetAndParseStrictJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "single object", body: `{"tree_size": 11, "timestamp": 99}`},
		{name: "single object with whitespace", body: "  {\"tree_size\": 11, \"timestamp\": 99}\n  "},
		{name: "ok with trailing garbage", body: `{"ok":true}garbage`, wantErr: "not a single complete JSON value"},
		{name: "two json objects", body: `{"ok":true} {"ok":true}`, wantErr: "not a single complete JSON value"},
		{name: "trailing null", body: `{"ok":true}null`, wantErr: "not a single complete JSON value"},
		{name: "truncated object", body: `{"tree_size": 11, "timestamp": 99`, wantErr: "unexpected EOF"},
		{name: "empty body", body: ``, wantErr: "EOF"},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := &scriptedRoundTripper{rsps: []*http.Response{newResponse(http.StatusOK, test.body)}}
			logClient, err := New("http://example.com", &http.Client{Transport: rt}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			var got TestStruct
			_, _, err = logClient.GetAndParse(ctx, "/struct/path", nil, &got)
			if test.wantErr == "" {
				if err != nil {
					t.Errorf("GetAndParse() = (_,_,%v), want nil error", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("GetAndParse() = (%+v,_,nil), want error containing %q", got, test.wantErr)
			}
			rspErr, ok := err.(RspError)
			if !ok {
				t.Fatalf("GetAndParse() error = %T, want RspError", err)
			}
			if !strings.Contains(rspErr.Err.Error(), test.wantErr) {
				t.Errorf("GetAndParse() error = %q, want error containing %q", rspErr.Err.Error(), test.wantErr)
			}
			if rspErr.StatusCode != http.StatusOK {
				t.Errorf("RspError.StatusCode = %d, want %d", rspErr.StatusCode, http.StatusOK)
			}
		})
	}
}

// TestRedirectAuthorizationHandling verifies that the Authorization header is
// stripped when a redirect crosses an authority boundary (including a port
// change) but is retained for redirects within the same authority.
func TestRedirectAuthorizationHandling(t *testing.T) {
	const authToken = "Bearer secret-token"
	tests := []struct {
		name          string
		location      string
		wantAuthOnHop []string // expected Authorization header per request hop
	}{
		{
			name:          "cross-port redirect strips authorization",
			location:      "http://example.com:9090/elsewhere",
			wantAuthOnHop: []string{authToken, ""},
		},
		{
			name:          "cross-host redirect strips authorization",
			location:      "http://other.example.com/elsewhere",
			wantAuthOnHop: []string{authToken, ""},
		},
		{
			name:          "cross-scheme redirect strips authorization",
			location:      "https://example.com/elsewhere",
			wantAuthOnHop: []string{authToken, ""},
		},
		{
			name:          "same-authority redirect keeps authorization",
			location:      "http://example.com/other/path",
			wantAuthOnHop: []string{authToken, authToken},
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			redirect := newResponse(http.StatusFound, "")
			redirect.Header.Set("Location", test.location)
			rt := &scriptedRoundTripper{rsps: []*http.Response{
				redirect,
				newResponse(http.StatusOK, `{"tree_size": 11, "timestamp": 99}`),
			}}
			logClient, err := New("http://example.com", &http.Client{Transport: rt}, Options{Authorization: authToken})
			if err != nil {
				t.Fatal(err)
			}
			var got TestStruct
			if _, _, err := logClient.GetAndParse(ctx, "/start", nil, &got); err != nil {
				t.Fatalf("GetAndParse() = (_,_,%v), want nil error", err)
			}
			if len(rt.requests) != len(test.wantAuthOnHop) {
				t.Fatalf("got %d request hops, want %d", len(rt.requests), len(test.wantAuthOnHop))
			}
			for i, want := range test.wantAuthOnHop {
				if got := rt.requests[i].Header.Get("Authorization"); got != want {
					t.Errorf("hop %d Authorization = %q, want %q", i, got, want)
				}
			}
		})
	}
}

// TestPostAndParseWithRetryStillWorks confirms that the normal retry path
// (retryable failure followed by success against the same log) is unaffected.
func TestPostAndParseWithRetryStillWorks(t *testing.T) {
	rt := &scriptedRoundTripper{rsps: []*http.Response{
		newResponse(http.StatusServiceUnavailable, "try later"),
		newResponse(http.StatusOK, `{"tree_size": 11, "timestamp": 99}`),
	}}
	logClient, err := New("http://example.com", &http.Client{Transport: rt}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	logClient.backoff = &mockBackoff{}

	var got TestStruct
	httpRsp, _, err := logClient.PostAndParseWithRetry(context.Background(), "/struct/path", TestParams{}, &got)
	if err != nil {
		t.Fatalf("PostAndParseWithRetry() = (_,_,%v), want nil error", err)
	}
	if httpRsp.StatusCode != http.StatusOK {
		t.Errorf("PostAndParseWithRetry() status = %d, want %d", httpRsp.StatusCode, http.StatusOK)
	}
	if want := (TestStruct{11, 99, ""}); !reflect.DeepEqual(got, want) {
		t.Errorf("PostAndParseWithRetry() = %+v, want %+v", got, want)
	}
	if len(rt.requests) != 2 {
		t.Errorf("got %d requests, want 2 (one retry)", len(rt.requests))
	}
}

// TestNewWrapsCheckRedirect verifies that a CheckRedirect configured on the
// caller's http.Client is still honoured, that the default redirect limit is
// preserved when none was configured, and that the caller's client is not
// mutated.
func TestNewWrapsCheckRedirect(t *testing.T) {
	t.Run("preserves caller CheckRedirect", func(t *testing.T) {
		called := false
		hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			called = true
			return nil
		}}
		logClient, err := New("http://example.com", hc, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if hc.CheckRedirect == nil {
			t.Fatal("New() mutated the caller's http.Client.CheckRedirect")
		}
		req := &http.Request{URL: mustParseURL(t, "http://example.com/x"), Header: http.Header{}}
		via := []*http.Request{{URL: mustParseURL(t, "http://example.com/start")}}
		if err := logClient.httpClient.CheckRedirect(req, via); err != nil {
			t.Errorf("CheckRedirect() = %v, want nil", err)
		}
		if !called {
			t.Error("caller-provided CheckRedirect was not invoked")
		}
	})

	t.Run("default redirect limit", func(t *testing.T) {
		logClient, err := New("http://example.com", &http.Client{}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		req := &http.Request{URL: mustParseURL(t, "http://example.com/x"), Header: http.Header{}}
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = &http.Request{URL: mustParseURL(t, "http://example.com/start")}
		}
		if err := logClient.httpClient.CheckRedirect(req, via); err == nil ||
			!strings.Contains(err.Error(), "stopped after 10 redirects") {
			t.Errorf("CheckRedirect() = %v, want error containing %q", err, "stopped after 10 redirects")
		}
	})
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", raw, err)
	}
	return u
}
