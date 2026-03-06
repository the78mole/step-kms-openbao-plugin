#!/bin/sh
# run-test.sh
# Integration test: verifies that the step-kms-openbao-plugin can interact
# with OpenBao Transit secrets engine.

set -e

echo "==> Integration Test: step-kms-openbao-plugin with OpenBao Transit"
echo ""

PLUGIN=/usr/local/bin/plugins/step-kms-openbao-plugin

# Check plugin binary exists
if [ ! -f "${PLUGIN}" ]; then
  echo "FAIL: Plugin binary not found at ${PLUGIN}"
  echo "      Build the plugin first and mount it into the container."
  exit 1
fi

echo "==> Test 1: Get public key for pre-created EC key..."
${PLUGIN} key "openbao:test-ec-key?address=${OPENBAO_ADDR}" || {
  echo "FAIL: Could not get public key for test-ec-key"
  exit 1
}
echo "PASS: Successfully retrieved EC public key"
echo ""

echo "==> Test 2: Get public key for pre-created RSA key..."
${PLUGIN} key "openbao:test-rsa-key?address=${OPENBAO_ADDR}" || {
  echo "FAIL: Could not get public key for test-rsa-key"
  exit 1
}
echo "PASS: Successfully retrieved RSA public key"
echo ""

echo "==> Test 3: Create a new EC P-384 key..."
${PLUGIN} create --kty EC --crv P384 "openbao:test-ec384-key?address=${OPENBAO_ADDR}" || {
  echo "FAIL: Could not create EC P-384 key"
  exit 1
}
echo "PASS: Successfully created EC P-384 key"
echo ""

echo "==> Test 4: Sign data with EC key..."
echo "Hello OpenBao" > /tmp/test-data.txt
${PLUGIN} sign --in /tmp/test-data.txt "openbao:test-ec-key?address=${OPENBAO_ADDR}" || {
  echo "FAIL: Could not sign data with EC key"
  exit 1
}
echo "PASS: Successfully signed data with EC key"
echo ""

echo ""
echo "============================================"
echo "  All integration tests PASSED!"
echo "============================================"
