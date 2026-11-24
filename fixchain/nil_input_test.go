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

package fixchain

import (
	"net/http"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
)

// TestFixNilInput makes sure that incomplete input fails closed: Fix must not
// panic on a nil leaf certificate or a nil chain member, must not produce any
// candidate chains, and must report the problem as a consumable FixError.
func TestFixNilInput(t *testing.T) {
	leaf := GetTestCertificateFromPEM(t, googleLeaf)
	intermediate := GetTestCertificateFromPEM(t, thawteIntermediate)
	roots := extractTestRoots(t, 0, []string{verisignRoot})
	client := &http.Client{Transport: &testRoundTripper{}}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		chain   []*x509.Certificate
		wantErr errorType
	}{
		{
			name:    "nil leaf, nil chain",
			cert:    nil,
			chain:   nil,
			wantErr: FixFailed,
		},
		{
			name:    "nil leaf with chain",
			cert:    nil,
			chain:   []*x509.Certificate{intermediate},
			wantErr: FixFailed,
		},
		{
			name:    "nil member in chain",
			cert:    leaf,
			chain:   []*x509.Certificate{nil, intermediate},
			wantErr: FixFailed,
		},
		{
			name:    "chain of only nil members",
			cert:    leaf,
			chain:   []*x509.Certificate{nil},
			wantErr: FixFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chains, ferrs := Fix(test.cert, test.chain, roots, client)
			if len(chains) != 0 {
				t.Fatalf("expected no chains for incomplete input, got %d", len(chains))
			}
			if len(ferrs) == 0 {
				t.Fatal("expected a FixError for incomplete input, got none")
			}
			found := false
			for _, ferr := range ferrs {
				if ferr.Type == test.wantErr && ferr.Error != nil {
					found = true
				}
				// The error itself must be consumable evidence.
				_ = ferr.String()
				if _, err := ferr.MarshalJSON(); err != nil {
					t.Errorf("FixError is not JSON-marshalable: %v", err)
				}
			}
			if !found {
				t.Errorf("expected a %s error carrying a cause, got %v",
					FixError{Type: test.wantErr}.TypeString(), ferrs)
			}
		})
	}
}

// TestFixerNilInput makes sure the asynchronous fixer also fails closed: a
// nil leaf or nil chain member must not crash a worker, must not result in a
// published chain, and must be reported through the errors channel.
func TestFixerNilInput(t *testing.T) {
	leaf := GetTestCertificateFromPEM(t, googleLeaf)
	intermediate := GetTestCertificateFromPEM(t, thawteIntermediate)
	roots := extractTestRoots(t, 0, []string{verisignRoot})

	tests := []struct {
		name  string
		cert  *x509.Certificate
		chain []*x509.Certificate
	}{
		{"nil leaf", nil, []*x509.Certificate{intermediate}},
		{"nil chain member", leaf, []*x509.Certificate{nil, intermediate}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chains := make(chan []*x509.Certificate)
			errors := make(chan *FixError)
			f := NewFixer(1, chains, errors,
				&http.Client{Transport: &testRoundTripper{}}, false)
			f.QueueChain(test.cert, test.chain, roots)

			done := make(chan struct{})
			var gotChains [][]*x509.Certificate
			var gotErrs []*FixError
			go func() {
				for chain := range chains {
					gotChains = append(gotChains, chain)
				}
			}()
			go func() {
				defer close(done)
				for ferr := range errors {
					gotErrs = append(gotErrs, ferr)
				}
			}()

			f.Wait()
			close(chains)
			close(errors)
			<-done

			if len(gotChains) != 0 {
				t.Errorf("expected no published chains, got %d", len(gotChains))
			}
			if len(gotErrs) == 0 {
				t.Fatal("expected a FixError for incomplete input, got none")
			}
			for _, ferr := range gotErrs {
				if ferr.Type != FixFailed || ferr.Error == nil {
					t.Errorf("expected a FixFailed error carrying a cause, got %+v", ferr)
				}
			}
		})
	}
}

// TestHandleChainKeepsRepairStages checks that valid but unverifiable input
// still goes through both repair stages: constructChain reports VerifyFailed,
// after which fixChain attempts the repair and reports FixFailed when no
// verifiable chain can be built against the supplied roots.
func TestHandleChainKeepsRepairStages(t *testing.T) {
	leaf := GetTestCertificateFromPEM(t, googleLeaf)
	fix := &toFix{
		cert:  leaf,
		chain: newDedupedChain(nil),
		roots: x509.NewCertPool(),
		cache: newURLCache(&http.Client{Transport: &testRoundTripper{}}, false),
	}

	chains, ferrs := fix.handleChain()
	if len(chains) != 0 {
		t.Errorf("expected no chains without any roots, got %d", len(chains))
	}
	matchTestErrorList(t, 0, []errorType{VerifyFailed, FixFailed}, ferrs)
}

// TestValidCompleteChainUnchanged makes sure a complete, verifiable chain is
// still published and produces no errors after the nil-input hardening.
func TestValidCompleteChainUnchanged(t *testing.T) {
	leaf := GetTestCertificateFromPEM(t, googleLeaf)
	chain := extractTestChain(t, 0, []string{thawteIntermediate, verisignRoot})
	roots := extractTestRoots(t, 0, []string{verisignRoot})

	chains, ferrs := Fix(leaf, chain, roots,
		&http.Client{Transport: &testRoundTripper{}})
	matchTestChainList(t, 0, [][]string{{"Google", "Thawte", "VeriSign"}}, chains)
	matchTestErrorList(t, 0, nil, ferrs)
}

// TestNilFixErrorIsConsumable checks that a FixError mentioning a nil chain
// member can still be rendered and serialized as evidence.
func TestNilFixErrorIsConsumable(t *testing.T) {
	ferr := &FixError{
		Type:  FixFailed,
		Chain: []*x509.Certificate{nil},
		Error: errNilChainMember,
	}
	if s := ferr.String(); s == "" {
		t.Error("expected a non-empty error string")
	}
	b, err := ferr.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() failed: %v", err)
	}
	parsed, err := UnmarshalJSON(b)
	if err != nil {
		t.Fatalf("UnmarshalJSON() failed: %v", err)
	}
	if parsed.Type != FixFailed {
		t.Errorf("expected FixFailed, got %s", parsed.TypeString())
	}
}

// TestNilSafeHashing covers the nil guards used by the queueing and logging
// paths before input reaches the fixer.
func TestNilSafeHashing(t *testing.T) {
	if h := hash(nil); h != [hashSize]byte{} {
		t.Errorf("hash(nil) = %x, want zero hash", h)
	}
	// nil members must simply be skipped rather than causing a panic.
	h1 := hashChain([]*x509.Certificate{nil})
	h2 := hashChain(nil)
	if h1 != h2 {
		t.Errorf("hashChain with nil member = %x, want %x", h1, h2)
	}
	// hashBag must not panic on chains containing nil members.
	_ = hashBag([]*x509.Certificate{nil, GetTestCertificateFromPEM(t, googleLeaf)})
}

// TestFixAndLogNilInput makes sure the fix-then-log entry points neither
// panic nor queue anything when handed incomplete chains.
func TestFixAndLogNilInput(t *testing.T) {
	tests := []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"nil chain", nil},
		{"empty chain", []*x509.Certificate{}},
		{"nil leaf at front", []*x509.Certificate{nil}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &Fixer{toFix: make(chan *toFix)}
			fl := &FixAndLog{
				fixer:  f,
				chains: make(chan []*x509.Certificate),
				logger: &Logger{postCertCache: newLockedMap()},
				done:   newLockedMap(),
			}

			// Neither call may panic.  Any queued fixes would block forever
			// because nothing drains f.toFix, so completing means the bad
			// input was rejected before reaching the fixer.
			fl.QueueChain(test.chain)
			if len(test.chain) == 0 {
				// A nil/empty chain is dropped before any root lookup.
				fl.QueueAllCertsInChain(test.chain)
			}
		})
	}
}

// TestQueueAllCertsInChainSkipsNilMember checks that a nil member inside an
// otherwise valid chain is skipped rather than queued for the fixer.
func TestQueueAllCertsInChainSkipsNilMember(t *testing.T) {
	leaf := GetTestCertificateFromPEM(t, googleLeaf)
	f := &Fixer{toFix: make(chan *toFix, 2)}
	fl := &FixAndLog{
		fixer:  f,
		chains: make(chan []*x509.Certificate),
		logger: &Logger{
			roots:          extractTestRoots(t, 0, []string{verisignRoot}),
			postCertCache:  newLockedMap(),
			postChainCache: newLockedMap(),
		},
		done: newLockedMap(),
	}

	fl.QueueAllCertsInChain([]*x509.Certificate{leaf, nil})
	close(f.toFix)

	var queued int
	for fix := range f.toFix {
		queued++
		if fix.cert == nil {
			t.Error("a nil certificate was queued for the fixer")
		}
		// The nil member stays in the queued chain so that handleChain() can
		// detect and reject it; assert that rejection here instead.
		if ferrs := fix.validate(); len(ferrs) == 0 {
			t.Error("expected validate() to reject the nil chain member")
		}
	}
	if queued != 1 {
		t.Errorf("expected exactly 1 queued fix (the leaf), got %d", queued)
	}
}

// TestLoggerNilInput makes sure the logger fails closed on incomplete chains.
func TestLoggerNilInput(t *testing.T) {
	errs := make(chan *FixError, 4)
	l := &Logger{
		toPost:         make(chan *toPost),
		errors:         errs,
		postCertCache:  newLockedMap(),
		postChainCache: newLockedMap(),
	}

	// QueueChain must simply ignore unusable input.
	l.QueueChain(nil)
	l.QueueChain([]*x509.Certificate{nil})

	// postChain must report a LogPostFailed error instead of panicking.
	l.postChain(&toPost{chain: []*x509.Certificate{nil}})
	select {
	case ferr := <-errs:
		if ferr.Type != LogPostFailed {
			t.Errorf("expected LogPostFailed, got %s", ferr.TypeString())
		}
	default:
		t.Error("expected a LogPostFailed error for a nil chain")
	}
}
