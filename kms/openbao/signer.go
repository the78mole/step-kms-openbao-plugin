//go:build !legacyvault

package openbao

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"

	vaultapi "github.com/hashicorp/vault/api"
)

// Signer implements the crypto.Signer interface using the OpenBao Transit
// secrets engine.
type Signer struct {
	client  *vaultapi.Client
	mount   string
	keyName string
	pub     crypto.PublicKey
}

// Public returns the public key associated with this signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the given digest using the Transit secrets engine.
//
// The digest must be pre-hashed. The opts parameter determines the hash
// function and, for RSA keys, whether to use PSS padding.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := hashAlgorithmName(opts.HashFunc())
	if hashAlg == "" {
		return nil, fmt.Errorf("openbao: unsupported hash function: %v", opts.HashFunc())
	}

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": hashAlg,
	}

	// For RSA keys, determine signature algorithm (PKCS#1 v1.5 or PSS)
	if _, ok := s.pub.(*rsa.PublicKey); ok {
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			data["signature_algorithm"] = "pss"
		} else {
			data["signature_algorithm"] = "pkcs1v15"
		}
	}

	// For Ed25519 keys, signing doesn't use prehashed mode
	if _, ok := s.pub.(ed25519.PublicKey); ok {
		data["prehashed"] = false
		delete(data, "hash_algorithm")
	}

	path := fmt.Sprintf("%s/sign/%s", s.mount, s.keyName)
	secret, err := s.client.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("openbao: error signing with key %q: %w", s.keyName, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("openbao: empty response from sign operation")
	}

	sigRaw, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("openbao: missing signature in response")
	}

	sig, err := parseTransitSignature(sigRaw)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// hashAlgorithmName maps crypto.Hash values to Transit API hash algorithm names.
func hashAlgorithmName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha2-256"
	case crypto.SHA384:
		return "sha2-384"
	case crypto.SHA512:
		return "sha2-512"
	case crypto.SHA224:
		return "sha2-224"
	default:
		return ""
	}
}
