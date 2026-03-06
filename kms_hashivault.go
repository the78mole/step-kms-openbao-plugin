//go:build legacyvault

package main

// Import the legacy HashiCorp Vault KMS backend.
// Build with -tags legacyvault to enable.
import _ "github.com/smallstep/step-kms-plugin/kms/hashivault"
