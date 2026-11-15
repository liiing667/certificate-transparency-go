// Copyright 2018 Google LLC. All Rights Reserved.
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

package ctutil

import (
	"encoding/base64"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509util"
)

func TestLeafHash(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		embedded bool
		want     string
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			want:     testdata.TestCertB64LeafHash,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			want:     testdata.TestPreCertB64LeafHash,
		},
		{
			desc:     "cert with embedded SCT",
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
			want:     testdata.TestPreCertB64LeafHash,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Parse chain
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			// Parse SCT
			var sct ct.SignedCertificateTimestamp
			if _, err = tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}

			// Test LeafHash()
			wantSl, err := base64.StdEncoding.DecodeString(test.want)
			if err != nil {
				t.Fatalf("error base64-decoding leaf hash %q: %s", test.want, err)
			}
			var want [32]byte
			copy(want[:], wantSl)

			got, err := LeafHash(chain, &sct, test.embedded)
			if got != want || err != nil {
				t.Errorf("LeafHash(_,_) = %v, %v, want %v, nil", got, err, want)
			}

			// Test LeafHashB64()
			gotB64, err := LeafHashB64(chain, &sct, test.embedded)
			if gotB64 != test.want || err != nil {
				t.Errorf("LeafHashB64(_,_) = %v, %v, want %v, nil", gotB64, err, test.want)
			}
		})
	}
}

func TestLeafHashErrors(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		embedded bool
	}{
		{
			desc:     "empty chain",
			chainPEM: "",
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "nil SCT",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      nil,
		},
		{
			desc:     "no SCTs embedded in cert, embedded true",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestInvalidProof,
			embedded: true,
		},
		{
			desc:     "cert contains embedded SCTs, but not the SCT provided",
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestInvalidProof,
			embedded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Parse chain
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			// Parse SCT
			var sct *ct.SignedCertificateTimestamp
			if test.sct != nil {
				sct = &ct.SignedCertificateTimestamp{}
				if _, err = tls.Unmarshal(test.sct, sct); err != nil {
					t.Fatalf("error tls-unmarshalling sct: %s", err)
				}
			}

			// Test LeafHash()
			got, err := LeafHash(chain, sct, test.embedded)
			if got != emptyHash || err == nil {
				t.Errorf("LeafHash(_,_) = %s, %v, want %v, error", got, err, emptyHash)
			}

			// Test LeafHashB64()
			gotB64, err := LeafHashB64(chain, sct, test.embedded)
			if gotB64 != "" || err == nil {
				t.Errorf("LeafHashB64(_,_) = %s, %v, want \"\", error", gotB64, err)
			}
		})
	}
}

func TestVerifySCT(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		embedded bool
		wantErr  bool
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "invalid SCT",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
		{
			desc:     "cert with embedded SCT",
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
		},
		{
			desc:     "cert with invalid embedded SCT",
			chainPEM: testdata.TestInvalidEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestInvalidProof,
			embedded: true,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Parse chain
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			// Parse SCT
			var sct ct.SignedCertificateTimestamp
			if _, err = tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}

			// Test VerifySCT()
			pk, err := ct.PublicKeyFromB64(testdata.LogPublicKeyB64)
			if err != nil {
				t.Errorf("error parsing public key: %s", err)
			}

			err = VerifySCT(pk, chain, &sct, test.embedded)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Errorf("VerifySCT(_,_,_, %t) = %v, want error? %t", test.embedded, err, test.wantErr)
			}
		})
	}
}

func TestVerifySCTWithVerifier(t *testing.T) {
	// Parse public key
	pk, err := ct.PublicKeyFromB64(testdata.LogPublicKeyB64)
	if err != nil {
		t.Errorf("error parsing public key: %s", err)
	}

	// Create signature verifier
	sv, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		t.Errorf("couldn't create signature verifier: %s", err)
	}

	tests := []struct {
		desc     string
		sv       *ct.SignatureVerifier
		chainPEM string
		sct      []byte
		embedded bool
		wantErr  bool
	}{
		{
			desc:     "nil signature verifier",
			sv:       nil,
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
		{
			desc:     "cert",
			sv:       sv,
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "precert",
			sv:       sv,
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "invalid SCT",
			sv:       sv,
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
		{
			desc:     "cert with embedded SCT",
			sv:       sv,
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
		},
		{
			desc:     "cert with invalid embedded SCT",
			sv:       sv,
			chainPEM: testdata.TestInvalidEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestInvalidProof,
			embedded: true,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Parse chain
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			// Parse SCT
			var sct ct.SignedCertificateTimestamp
			if _, err = tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}

			// Test VerifySCTWithVerifier()
			err = VerifySCTWithVerifier(test.sv, chain, &sct, test.embedded)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Errorf("VerifySCT(_,_,_, %t) = %v, want error? %t", test.embedded, err, test.wantErr)
			}
		})
	}
}

func TestContainsSCT(t *testing.T) {
	tests := []struct {
		desc    string
		certPEM string
		sct     []byte
		want    bool
	}{
		{
			desc:    "cert doesn't contain any SCTs",
			certPEM: testdata.TestCertPEM,
			sct:     testdata.TestPreCertProof,
			want:    false,
		},
		{
			desc:    "cert contains SCT but not specified SCT",
			certPEM: testdata.TestEmbeddedCertPEM,
			sct:     testdata.TestInvalidProof,
			want:    false,
		},
		{
			desc:    "cert contains SCT",
			certPEM: testdata.TestEmbeddedCertPEM,
			sct:     testdata.TestPreCertProof,
			want:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Parse cert
			cert, err := x509util.CertificateFromPEM([]byte(test.certPEM))
			if err != nil {
				t.Fatalf("error parsing certificate: %s", err)
			}

			// Parse SCT
			var sct ct.SignedCertificateTimestamp
			if _, err = tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}

			// Test ContainsSCT()
			got, err := ContainsSCT(cert, &sct)
			if err != nil {
				t.Fatalf("ContainsSCT(_,_) = false, %s, want no error", err)
			}

			if got != test.want {
				t.Errorf("ContainsSCT(_,_) = %t, nil, want %t, nil", got, test.want)
			}
		})
	}
}

// tamperSCTLogID replaces the SCT's LogID with an unrelated, non-empty value.
// The signature itself remains valid, so only a LogID binding check can detect
// that the SCT claims to originate from a different log.
func tamperSCTLogID(t *testing.T, sct *ct.SignedCertificateTimestamp) {
	t.Helper()
	for i := range sct.LogID.KeyID {
		sct.LogID.KeyID[i] = ^sct.LogID.KeyID[i]
	}
}

func TestVerifySCTRejectsEmptyLogID(t *testing.T) {
	pk, err := ct.PublicKeyFromB64(testdata.LogPublicKeyB64)
	if err != nil {
		t.Fatalf("error parsing public key: %s", err)
	}

	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		embedded bool
	}{
		{
			desc:     "non-embedded cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "non-embedded precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "embedded cert",
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			var sct ct.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}
			sct.LogID = ct.LogID{}

			if test.embedded {
				// The embedded-path checks that the SCT is present in the cert,
				// so keep the cert's embedded copy of the tampered SCT in sync.
				raw, err := tls.Marshal(sct)
				if err != nil {
					t.Fatalf("error tls-marshalling sct: %s", err)
				}
				chain[0].SCTList.SCTList[0].Val = raw
			}

			if err := VerifySCT(pk, chain, &sct, test.embedded); err == nil {
				t.Errorf("VerifySCT(embedded=%t) accepted an SCT with empty LogID", test.embedded)
			}
		})
	}
}

func TestVerifySCTRejectsMismatchedLogID(t *testing.T) {
	pk, err := ct.PublicKeyFromB64(testdata.LogPublicKeyB64)
	if err != nil {
		t.Fatalf("error parsing public key: %s", err)
	}

	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		embedded bool
	}{
		{
			desc:     "non-embedded cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "non-embedded precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "embedded cert",
			chainPEM: testdata.TestEmbeddedCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
			if err != nil {
				t.Fatalf("error parsing certificate chain: %s", err)
			}

			var sct ct.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(test.sct, &sct); err != nil {
				t.Fatalf("error tls-unmarshalling sct: %s", err)
			}
			tamperSCTLogID(t, &sct)

			if test.embedded {
				raw, err := tls.Marshal(sct)
				if err != nil {
					t.Fatalf("error tls-marshalling sct: %s", err)
				}
				chain[0].SCTList.SCTList[0].Val = raw
			}

			if err := VerifySCT(pk, chain, &sct, test.embedded); err == nil {
				t.Errorf("VerifySCT(embedded=%t) accepted an SCT whose LogID does not match the verifying key", test.embedded)
			}
		})
	}
}

func TestVerifySCTWithVerifierRejectsMismatchedLogID(t *testing.T) {
	pk, err := ct.PublicKeyFromB64(testdata.LogPublicKeyB64)
	if err != nil {
		t.Fatalf("error parsing public key: %s", err)
	}
	sv, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		t.Fatalf("couldn't create signature verifier: %s", err)
	}

	chain, err := x509util.CertificatesFromPEM([]byte(testdata.TestCertPEM + testdata.CACertPEM))
	if err != nil {
		t.Fatalf("error parsing certificate chain: %s", err)
	}

	var sct ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(testdata.TestCertProof, &sct); err != nil {
		t.Fatalf("error tls-unmarshalling sct: %s", err)
	}
	tamperSCTLogID(t, &sct)

	if err := VerifySCTWithVerifier(sv, chain, &sct, false); err == nil {
		t.Error("VerifySCTWithVerifier() accepted an SCT whose LogID does not match the verifier key")
	}
}
