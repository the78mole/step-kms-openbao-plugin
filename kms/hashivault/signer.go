//go:build legacyvault

package hashivault

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"

	vaultapi "github.com/hashicorp/vault/api"
)

// Signer implements the crypto.Signer interface using HashiCorp Vault's Transit
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
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := hashAlgorithmName(opts.HashFunc())
	if hashAlg == "" {
		return nil, fmt.Errorf("hashivault: unsupported hash function: %v", opts.HashFunc())
	}

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": hashAlg,
	}

	if _, ok := s.pub.(*rsa.PublicKey); ok {
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			data["signature_algorithm"] = "pss"
		} else {
			data["signature_algorithm"] = "pkcs1v15"
		}
	}

	if _, ok := s.pub.(ed25519.PublicKey); ok {
		data["prehashed"] = false
		delete(data, "hash_algorithm")
	}

	path := fmt.Sprintf("%s/sign/%s", s.mount, s.keyName)
	secret, err := s.client.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error signing with key %q: %w", s.keyName, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("hashivault: empty response from sign operation")
	}

	sigRaw, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("hashivault: missing signature in response")
	}

	sig, err := parseTransitSignature(sigRaw)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

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
