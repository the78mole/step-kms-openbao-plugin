//go:build integration && !legacyvault

package openbao

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
)

// These integration tests require a running OpenBao instance with Transit
// secrets engine enabled.
//
// Required environment variables:
//   - OPENBAO_ADDR: Address of the OpenBao server (e.g., http://127.0.0.1:8200)
//   - OPENBAO_TOKEN: Root or sufficiently-privileged token
//
// Run with:
//   go test -tags integration ./kms/openbao/ -v
//
// Or use the Makefile target:
//   make integration-test

func skipIfNoOpenBao(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENBAO_ADDR") == "" || os.Getenv("OPENBAO_TOKEN") == "" {
		t.Skip("Skipping integration test: OPENBAO_ADDR and OPENBAO_TOKEN must be set")
	}
}

func newTestKMS(t *testing.T) *OpenBaoKMS {
	t.Helper()
	skipIfNoOpenBao(t)

	km, err := New(context.Background(), apiv1.Options{
		URI: "openbao:mount=transit",
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return km
}

func TestIntegration_CreateKey_ECDSA_P256(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-ec-p256",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		t.Fatalf("CreateKey(EC P-256) failed: %v", err)
	}

	if resp.Name == "" {
		t.Error("CreateKey returned empty name")
	}
	if resp.PublicKey == nil {
		t.Fatal("CreateKey returned nil public key")
	}

	ecKey, ok := resp.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", resp.PublicKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}
	t.Logf("Created EC P-256 key: %s", resp.Name)
}

func TestIntegration_CreateKey_ECDSA_P384(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-ec-p384",
		SignatureAlgorithm: apiv1.ECDSAWithSHA384,
	})
	if err != nil {
		t.Fatalf("CreateKey(EC P-384) failed: %v", err)
	}

	ecKey, ok := resp.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", resp.PublicKey)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Errorf("expected P-384 curve, got %v", ecKey.Curve.Params().Name)
	}
	t.Logf("Created EC P-384 key: %s", resp.Name)
}

func TestIntegration_CreateKey_RSA_2048(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-rsa-2048",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               2048,
	})
	if err != nil {
		t.Fatalf("CreateKey(RSA-2048) failed: %v", err)
	}

	rsaKey, ok := resp.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", resp.PublicKey)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d bits", rsaKey.N.BitLen())
	}
	t.Logf("Created RSA-2048 key: %s", resp.Name)
}

func TestIntegration_CreateKey_RSA_4096(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-rsa-4096",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               4096,
	})
	if err != nil {
		t.Fatalf("CreateKey(RSA-4096) failed: %v", err)
	}

	rsaKey, ok := resp.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", resp.PublicKey)
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("expected 4096-bit key, got %d bits", rsaKey.N.BitLen())
	}
	t.Logf("Created RSA-4096 key: %s", resp.Name)
}

func TestIntegration_GetPublicKey(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	// First create a key
	createResp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-getpub",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Then retrieve the public key
	pub, err := km.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: createResp.Name,
	})
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}

	// Verify it matches the key from create
	origKey, ok := createResp.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CreateKey returned %T, expected *ecdsa.PublicKey", createResp.PublicKey)
	}
	if !ecKey.Equal(origKey) {
		t.Error("GetPublicKey returned a different key than CreateKey")
	}
	t.Logf("GetPublicKey returned matching EC P-256 key")
}

func TestIntegration_CreateSigner_ECDSA(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	// Create a key
	createResp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-signer-ec",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Create a signer
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: createResp.Name,
	})
	if err != nil {
		t.Fatalf("CreateSigner failed: %v", err)
	}

	// Sign some data
	message := []byte("Hello, OpenBao Transit integration test!")
	digest := sha256.Sum256(message)

	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	// Verify the signature
	ecKey := createResp.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(ecKey, digest[:], sig) {
		t.Error("ECDSA signature verification failed")
	} else {
		t.Log("ECDSA signature verified successfully")
	}
}

func TestIntegration_CreateSigner_RSA_PKCS1(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	// Create a key
	createResp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-signer-rsa",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               2048,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Create a signer
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: createResp.Name,
	})
	if err != nil {
		t.Fatalf("CreateSigner failed: %v", err)
	}

	// Sign some data
	message := []byte("Hello, RSA PKCS#1 signing via OpenBao Transit!")
	digest := sha256.Sum256(message)

	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	// Verify the signature
	rsaKey := createResp.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sig)
	if err != nil {
		t.Errorf("RSA PKCS#1 signature verification failed: %v", err)
	} else {
		t.Log("RSA PKCS#1 signature verified successfully")
	}
}

func TestIntegration_CreateSigner_RSA_PSS(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	// Create a key
	createResp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-signer-rsa-pss",
		SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
		Bits:               2048,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Create a signer
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: createResp.Name,
	})
	if err != nil {
		t.Fatalf("CreateSigner failed: %v", err)
	}

	// Sign some data with PSS
	message := []byte("Hello, RSA-PSS signing via OpenBao Transit!")
	digest := sha256.Sum256(message)

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	sig, err := signer.Sign(rand.Reader, digest[:], pssOpts)
	if err != nil {
		t.Fatalf("Sign with PSS failed: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	// Verify the PSS signature
	rsaKey := createResp.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPSS(rsaKey, crypto.SHA256, digest[:], sig, pssOpts)
	if err != nil {
		t.Errorf("RSA-PSS signature verification failed: %v", err)
	} else {
		t.Log("RSA-PSS signature verified successfully")
	}
}

func TestIntegration_SignerPublicKeyMatchesCreate(t *testing.T) {
	km := newTestKMS(t)
	defer km.Close()

	// Create a key
	createResp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "integration-test-signer-pubkey",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Create a signer
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: createResp.Name,
	})
	if err != nil {
		t.Fatalf("CreateSigner failed: %v", err)
	}

	// Check the public key matches
	signerPub := signer.Public()
	createPub := createResp.PublicKey

	ecSigner, ok := signerPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signer.Public() returned %T, expected *ecdsa.PublicKey", signerPub)
	}
	ecCreate, ok := createPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CreateKey returned %T, expected *ecdsa.PublicKey", createPub)
	}

	if !ecSigner.Equal(ecCreate) {
		t.Error("signer.Public() does not match CreateKey response public key")
	} else {
		t.Log("Signer public key matches CreateKey response")
	}
}
