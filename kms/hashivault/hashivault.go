//go:build legacyvault

// Package hashivault implements a legacy KMS backend for HashiCorp Vault's
// Transit secrets engine. Build with -tags legacyvault to enable.
package hashivault

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

// Scheme is the URI scheme used by the HashiCorp Vault KMS.
const Scheme = "hashivault"

// HashiVaultKMS implements the apiv1.KeyManager interface using HashiCorp
// Vault's Transit secrets engine.
type HashiVaultKMS struct {
	client *vaultapi.Client
	mount  string
}

// Type is the KMS type for HashiCorp Vault.
const Type = apiv1.Type(Scheme)

func init() {
	apiv1.Register(Type, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// New creates a new HashiVaultKMS backed by the Transit secrets engine.
//
// Configuration is read from the URI and environment variables:
//   - VAULT_ADDR: the address of the Vault server
//   - VAULT_TOKEN: the authentication token
//   - VAULT_CACERT: path to a CA certificate for TLS
//   - VAULT_CLIENT_CERT: path to a client certificate for mTLS
//   - VAULT_CLIENT_KEY: path to a client key for mTLS
//
// URI parameters:
//   - mount: the Transit mount path (default: "transit")
//   - address / addr: the Vault server address
//   - token: the authentication token
//   - role-id, secret-id: for AppRole authentication
//   - ca-cert: path to a CA certificate for TLS
//   - client-cert, client-key: paths for mTLS
func New(_ context.Context, opts apiv1.Options) (*HashiVaultKMS, error) {
	cfg := vaultapi.DefaultConfig()

	mount := "transit"

	// Parse URI for configuration parameters
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, fmt.Errorf("hashivault: error parsing URI: %w", err)
		}

		if v := u.Get("mount"); v != "" {
			mount = v
		}

		if v := u.Get("address"); v != "" {
			cfg.Address = v
		} else if v := u.Get("addr"); v != "" {
			cfg.Address = v
		}

		if v := u.Get("ca-cert"); v != "" {
			tlsCfg := &vaultapi.TLSConfig{CACert: v}
			if err := cfg.ConfigureTLS(tlsCfg); err != nil {
				return nil, fmt.Errorf("hashivault: error configuring TLS: %w", err)
			}
		}

		clientCert := u.Get("client-cert")
		clientKey := u.Get("client-key")
		if clientCert != "" && clientKey != "" {
			tlsCfg := &vaultapi.TLSConfig{
				ClientCert: clientCert,
				ClientKey:  clientKey,
			}
			if err := cfg.ConfigureTLS(tlsCfg); err != nil {
				return nil, fmt.Errorf("hashivault: error configuring mTLS: %w", err)
			}
		}
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error creating client: %w", err)
	}

	// Set token from URI parameter if provided
	if opts.URI != "" {
		u, _ := uri.ParseWithScheme(Scheme, opts.URI)
		if u != nil {
			if v := u.Get("token"); v != "" {
				client.SetToken(v)
			}
		}
	}

	// AppRole authentication if role-id and secret-id are provided
	if opts.URI != "" {
		u, _ := uri.ParseWithScheme(Scheme, opts.URI)
		if u != nil {
			roleID := u.Get("role-id")
			secretID := u.Get("secret-id")
			if roleID != "" && secretID != "" {
				if err := appRoleLogin(client, roleID, secretID); err != nil {
					return nil, err
				}
			}
		}
	}

	return &HashiVaultKMS{
		client: client,
		mount:  mount,
	}, nil
}

// appRoleLogin performs AppRole authentication and sets the token on the client.
func appRoleLogin(client *vaultapi.Client, roleID, secretID string) error {
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("hashivault: AppRole login failed: %w", err)
	}
	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("hashivault: AppRole login returned empty response")
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

// Close is a no-op for the HashiVault KMS.
func (k *HashiVaultKMS) Close() error {
	return nil
}

// CreateKey creates a new asymmetric key in the Transit secrets engine.
func (k *HashiVaultKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("hashivault: key name is required")
	}

	keyName := parseName(req.Name)
	keyType := signatureAlgorithmToTransitKeyType(req.SignatureAlgorithm, req.Bits)

	data := map[string]interface{}{
		"type":       keyType,
		"exportable": false,
	}

	path := fmt.Sprintf("%s/keys/%s", k.mount, keyName)
	_, err := k.client.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error creating key %q: %w", keyName, err)
	}

	pub, err := k.readPublicKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error reading public key after creation: %w", err)
	}

	name := Scheme + ":" + keyName
	return &apiv1.CreateKeyResponse{
		Name:      name,
		PublicKey: pub,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: name,
		},
	}, nil
}

// GetPublicKey retrieves the public key for a Transit key.
func (k *HashiVaultKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("hashivault: key name is required")
	}
	keyName := parseName(req.Name)
	return k.readPublicKey(keyName)
}

// CreateSigner returns a crypto.Signer that signs using the Transit secrets engine.
func (k *HashiVaultKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, fmt.Errorf("hashivault: signing key name is required")
	}
	keyName := parseName(req.SigningKey)

	pub, err := k.readPublicKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error reading public key for signer: %w", err)
	}

	return &Signer{
		client:  k.client,
		mount:   k.mount,
		keyName: keyName,
		pub:     pub,
	}, nil
}

// readPublicKey reads the latest public key for a Transit key.
func (k *HashiVaultKMS) readPublicKey(keyName string) (crypto.PublicKey, error) {
	path := fmt.Sprintf("%s/keys/%s", k.mount, keyName)
	secret, err := k.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error reading key %q: %w", keyName, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("hashivault: key %q not found", keyName)
	}

	latestVersionRaw, ok := secret.Data["latest_version"]
	if !ok {
		return nil, fmt.Errorf("hashivault: key %q missing latest_version field", keyName)
	}

	latestVersion, err := toInt(latestVersionRaw)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error parsing latest_version for key %q: %w", keyName, err)
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("hashivault: key %q missing keys field", keyName)
	}

	keysMap, ok := keysRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hashivault: unexpected keys format for key %q", keyName)
	}

	versionKey := fmt.Sprintf("%d", latestVersion)
	versionData, ok := keysMap[versionKey]
	if !ok {
		return nil, fmt.Errorf("hashivault: version %d not found for key %q", latestVersion, keyName)
	}

	versionMap, ok := versionData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hashivault: unexpected version data format for key %q", keyName)
	}

	pubKeyPEM, ok := versionMap["public_key"].(string)
	if !ok || pubKeyPEM == "" {
		return nil, fmt.Errorf("hashivault: no public_key found for key %q (is it an asymmetric key?)", keyName)
	}

	return parsePublicKeyPEM(pubKeyPEM)
}

func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("hashivault: failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hashivault: error parsing public key: %w", err)
	}
	return pub, nil
}

func parseName(name string) string {
	name = strings.TrimPrefix(name, Scheme+":")
	name = strings.TrimPrefix(name, strings.ToUpper(Scheme)+":")
	return name
}

func signatureAlgorithmToTransitKeyType(alg apiv1.SignatureAlgorithm, bits int) string {
	switch alg {
	case apiv1.ECDSAWithSHA256:
		return "ecdsa-p256"
	case apiv1.ECDSAWithSHA384:
		return "ecdsa-p384"
	case apiv1.ECDSAWithSHA512:
		return "ecdsa-p521"
	case apiv1.SHA256WithRSA, apiv1.SHA384WithRSA, apiv1.SHA512WithRSA,
		apiv1.SHA256WithRSAPSS, apiv1.SHA384WithRSAPSS, apiv1.SHA512WithRSAPSS:
		return rsaKeyType(bits)
	case apiv1.PureEd25519:
		return "ed25519"
	default:
		return "ecdsa-p256"
	}
}

func rsaKeyType(bits int) string {
	switch {
	case bits >= 4096:
		return "rsa-4096"
	case bits >= 3072:
		return "rsa-3072"
	default:
		return "rsa-2048"
	}
}

func toInt(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		if s, ok := v.(fmt.Stringer); ok {
			var i int64
			_, err := fmt.Sscanf(s.String(), "%d", &i)
			return i, err
		}
		return 0, fmt.Errorf("unsupported numeric type %T", v)
	}
}

func parseTransitSignature(sig string) ([]byte, error) {
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("hashivault: unexpected signature format: %s", sig)
	}
	b, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("hashivault: error decoding signature: %w", err)
	}
	return b, nil
}
