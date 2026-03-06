//go:build !legacyvault

package main

// Import the OpenBao KMS backend (default).
import _ "github.com/smallstep/step-kms-plugin/kms/openbao"
