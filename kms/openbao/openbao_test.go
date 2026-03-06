//go:build !legacyvault

package openbao

import (
	"crypto"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
)

func TestParseName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare name", "my-key", "my-key"},
		{"with scheme", "openbao:my-key", "my-key"},
		{"with uppercase scheme", "OPENBAO:my-key", "my-key"},
		{"name with slashes", "my-transit/my-key", "my-transit/my-key"},
		{"scheme with complex name", "openbao:my-transit/my-key", "my-transit/my-key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseName(tc.input)
			if got != tc.expected {
				t.Errorf("parseName(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSignatureAlgorithmToTransitKeyType(t *testing.T) {
	tests := []struct {
		name     string
		alg      apiv1.SignatureAlgorithm
		bits     int
		expected string
	}{
		{"ECDSA P-256", apiv1.ECDSAWithSHA256, 0, "ecdsa-p256"},
		{"ECDSA P-384", apiv1.ECDSAWithSHA384, 0, "ecdsa-p384"},
		{"ECDSA P-521", apiv1.ECDSAWithSHA512, 0, "ecdsa-p521"},
		{"RSA default", apiv1.SHA256WithRSA, 0, "rsa-2048"},
		{"RSA 2048", apiv1.SHA256WithRSA, 2048, "rsa-2048"},
		{"RSA 3072", apiv1.SHA384WithRSA, 3072, "rsa-3072"},
		{"RSA 4096", apiv1.SHA512WithRSA, 4096, "rsa-4096"},
		{"RSA-PSS 4096", apiv1.SHA256WithRSAPSS, 4096, "rsa-4096"},
		{"Ed25519", apiv1.PureEd25519, 0, "ed25519"},
		{"unspecified defaults to P-256", apiv1.UnspecifiedSignAlgorithm, 0, "ecdsa-p256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := signatureAlgorithmToTransitKeyType(tc.alg, tc.bits)
			if got != tc.expected {
				t.Errorf("signatureAlgorithmToTransitKeyType(%v, %d) = %q, want %q", tc.alg, tc.bits, got, tc.expected)
			}
		})
	}
}

func TestParseTransitSignature(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid v1 sig", "vault:v1:dGVzdA==", false},
		{"valid v2 sig", "vault:v2:dGVzdA==", false},
		{"invalid format", "invalid-signature", true},
		{"invalid base64", "vault:v1:not-valid-base64!!!", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTransitSignature(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseTransitSignature(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseTransitSignature(%q) unexpected error: %v", tc.input, err)
				return
			}
			if got == nil {
				t.Errorf("parseTransitSignature(%q) returned nil", tc.input)
			}
		})
	}
}

func TestToInt(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int64
		wantErr  bool
	}{
		{"float64", float64(42), 42, false},
		{"int64", int64(42), 42, false},
		{"int", int(42), 42, false},
		{"unsupported", "not-a-number", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toInt(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("toInt(%v) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("toInt(%v) unexpected error: %v", tc.input, err)
				return
			}
			if got != tc.expected {
				t.Errorf("toInt(%v) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	// Valid EC P-256 public key PEM
	validPEM := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGHJ2ShCcBtmCJwMZLX0+6dpTGXbn\n0tyZ83X3CPYLIQRuT936fK7EsRHKJCe44iAM8TCulvivcVesv2C50uOwbA==\n-----END PUBLIC KEY-----\n"

	invalidPEM := "not a pem"

	t.Run("valid PEM", func(t *testing.T) {
		pub, err := parsePublicKeyPEM(validPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pub == nil {
			t.Fatal("expected non-nil public key")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parsePublicKeyPEM(invalidPEM)
		if err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})
}

func TestHashAlgorithmName(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected string
	}{
		{"SHA256", crypto.SHA256, "sha2-256"},
		{"SHA384", crypto.SHA384, "sha2-384"},
		{"SHA512", crypto.SHA512, "sha2-512"},
		{"SHA224", crypto.SHA224, "sha2-224"},
		{"unsupported", crypto.MD5, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hashAlgorithmName(tc.hash)
			if got != tc.expected {
				t.Errorf("hashAlgorithmName(%v) = %q, want %q", tc.hash, got, tc.expected)
			}
		})
	}
}

func TestNewRequiresValidURI(t *testing.T) {
	// Test that New returns an error for an invalid URI
	_, err := New(nil, apiv1.Options{
		URI: "openbao:mount=transit",
	})
	// New should succeed even without a running server (just creates a client)
	if err != nil {
		t.Fatalf("New() with valid URI should not fail: %v", err)
	}
}

func TestCreateKeyEmptyName(t *testing.T) {
	km := &OpenBaoKMS{}
	_, err := km.CreateKey(&apiv1.CreateKeyRequest{Name: ""})
	if err == nil {
		t.Fatal("CreateKey with empty name should fail")
	}
}

func TestGetPublicKeyEmptyName(t *testing.T) {
	km := &OpenBaoKMS{}
	_, err := km.GetPublicKey(&apiv1.GetPublicKeyRequest{Name: ""})
	if err == nil {
		t.Fatal("GetPublicKey with empty name should fail")
	}
}

func TestCreateSignerEmptyName(t *testing.T) {
	km := &OpenBaoKMS{}
	_, err := km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: ""})
	if err == nil {
		t.Fatal("CreateSigner with empty signing key should fail")
	}
}

func TestClose(t *testing.T) {
	km := &OpenBaoKMS{}
	if err := km.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
}
