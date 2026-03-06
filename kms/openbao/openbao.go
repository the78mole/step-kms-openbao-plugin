//go:build !legacyvault

// Package openbao implements a KMS backend for OpenBao's Transit secrets engine.
// It uses the github.com/hashicorp/vault/api client for API compatibility.
package openbao

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

// Scheme is the URI scheme used by the OpenBao KMS.
const Scheme = "openbao"

// OpenBaoKMS implements the apiv1.KeyManager interface using OpenBao's Transit
// secrets engine.
type OpenBaoKMS struct {
	client *vaultapi.Client
	mount  string
}

// Type is the KMS type for OpenBao.
const Type = apiv1.Type(Scheme)

func init() {
	apiv1.Register(Type, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// New creates a new OpenBaoKMS backed by the Transit secrets engine.
//
// Configuration is read from the URI and the following environment variables:
//   - OPENBAO_ADDR / VAULT_ADDR: the address of the OpenBao server
//   - OPENBAO_TOKEN / VAULT_TOKEN: the authentication token
//   - OPENBAO_CACERT / VAULT_CACERT: path to a CA certificate for TLS
//   - OPENBAO_CLIENT_CERT / VAULT_CLIENT_CERT: path to a client certificate for mTLS
//   - OPENBAO_CLIENT_KEY / VAULT_CLIENT_KEY: path to a client key for mTLS
//
// URI parameters:
//   - mount: the Transit mount path (default: "transit")
//   - address / addr: the OpenBao server address
//   - token: the authentication token
//   - role-id, secret-id: for AppRole authentication
//   - ca-cert: path to a CA certificate for TLS
//   - client-cert, client-key: paths for mTLS
func New(_ context.Context, opts apiv1.Options) (*OpenBaoKMS, error) {
	cfg := vaultapi.DefaultConfig()

	mount := "transit"

	// Parse URI for configuration parameters
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, fmt.Errorf("openbao: error parsing URI: %w", err)
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
				return nil, fmt.Errorf("openbao: error configuring TLS: %w", err)
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
				return nil, fmt.Errorf("openbao: error configuring mTLS: %w", err)
			}
		}
	}

	// Override address from OPENBAO_ADDR if set (takes precedence over VAULT_ADDR)
	if v := os.Getenv("OPENBAO_ADDR"); v != "" {
		cfg.Address = v
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("openbao: error creating client: %w", err)
	}

	// Set token: URI parameter > OPENBAO_TOKEN env > VAULT_TOKEN env (already set by client)
	if opts.URI != "" {
		u, _ := uri.ParseWithScheme(Scheme, opts.URI)
		if u != nil {
			if v := u.Get("token"); v != "" {
				client.SetToken(v)
			}
		}
	}
	if v := os.Getenv("OPENBAO_TOKEN"); v != "" {
		client.SetToken(v)
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

	return &OpenBaoKMS{
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
		return fmt.Errorf("openbao: AppRole login failed: %w", err)
	}
	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("openbao: AppRole login returned empty response")
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

// Close is a no-op for the OpenBao KMS.
func (k *OpenBaoKMS) Close() error {
	return nil
}

// CreateKey creates a new asymmetric key in the Transit secrets engine.
func (k *OpenBaoKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("openbao: key name is required")
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
		return nil, fmt.Errorf("openbao: error creating key %q: %w", keyName, err)
	}

	pub, err := k.readPublicKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("openbao: error reading public key after creation: %w", err)
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
func (k *OpenBaoKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("openbao: key name is required")
	}
	keyName := parseName(req.Name)
	return k.readPublicKey(keyName)
}

// CreateSigner returns a crypto.Signer that signs using the Transit secrets engine.
func (k *OpenBaoKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, fmt.Errorf("openbao: signing key name is required")
	}
	keyName := parseName(req.SigningKey)

	pub, err := k.readPublicKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("openbao: error reading public key for signer: %w", err)
	}

	return &Signer{
		client:  k.client,
		mount:   k.mount,
		keyName: keyName,
		pub:     pub,
	}, nil
}

// readPublicKey reads the latest public key for a Transit key.
func (k *OpenBaoKMS) readPublicKey(keyName string) (crypto.PublicKey, error) {
	path := fmt.Sprintf("%s/keys/%s", k.mount, keyName)
	secret, err := k.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("openbao: error reading key %q: %w", keyName, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("openbao: key %q not found", keyName)
	}

	// Get the latest version number
	latestVersionRaw, ok := secret.Data["latest_version"]
	if !ok {
		return nil, fmt.Errorf("openbao: key %q missing latest_version field", keyName)
	}

	// latestVersionRaw could be json.Number or float64
	latestVersion, err := toInt(latestVersionRaw)
	if err != nil {
		return nil, fmt.Errorf("openbao: error parsing latest_version for key %q: %w", keyName, err)
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("openbao: key %q missing keys field", keyName)
	}

	keysMap, ok := keysRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("openbao: unexpected keys format for key %q", keyName)
	}

	versionKey := fmt.Sprintf("%d", latestVersion)
	versionData, ok := keysMap[versionKey]
	if !ok {
		return nil, fmt.Errorf("openbao: version %d not found for key %q", latestVersion, keyName)
	}

	versionMap, ok := versionData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("openbao: unexpected version data format for key %q", keyName)
	}

	pubKeyPEM, ok := versionMap["public_key"].(string)
	if !ok || pubKeyPEM == "" {
		return nil, fmt.Errorf("openbao: no public_key found for key %q (is it an asymmetric key?)", keyName)
	}

	return parsePublicKeyPEM(pubKeyPEM)
}

// parsePublicKeyPEM parses a PEM-encoded public key.
func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("openbao: failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("openbao: error parsing public key: %w", err)
	}
	return pub, nil
}

// parseName strips the openbao: scheme prefix from a key name if present.
func parseName(name string) string {
	name = strings.TrimPrefix(name, Scheme+":")
	// Also handle uppercase
	name = strings.TrimPrefix(name, strings.ToUpper(Scheme)+":")
	return name
}

// signatureAlgorithmToTransitKeyType maps apiv1.SignatureAlgorithm to Transit
// key type strings.
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

// toInt converts a numeric interface{} value to int64.
// Vault API may return json.Number or float64 depending on the client config.
func toInt(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		// json.Number
		if s, ok := v.(fmt.Stringer); ok {
			var i int64
			_, err := fmt.Sscanf(s.String(), "%d", &i)
			return i, err
		}
		return 0, fmt.Errorf("unsupported numeric type %T", v)
	}
}

// parseTransitSignature strips the vault:vN: prefix from a Transit signature
// and returns the raw base64-decoded bytes.
func parseTransitSignature(sig string) ([]byte, error) {
	// Format is "vault:v1:<base64>" or "vault:vN:<base64>"
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("openbao: unexpected signature format: %s", sig)
	}
	b, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("openbao: error decoding signature: %w", err)
	}
	return b, nil
}
