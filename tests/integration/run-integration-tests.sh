#!/bin/bash
# tests/integration/run-integration-tests.sh
#
# Self-contained script that:
# 1. Starts OpenBao in Docker dev mode
# 2. Enables the Transit secrets engine
# 3. Builds the plugin
# 4. Runs CLI-based and Go integration tests
# 5. Cleans up
#
# Usage:
#   ./tests/integration/run-integration-tests.sh
#
# Requirements: Docker, Go

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTAINER_NAME="openbao-integration-test"
OPENBAO_PORT=8200
OPENBAO_ADDR="http://127.0.0.1:${OPENBAO_PORT}"
OPENBAO_TOKEN="dev-root-token"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    echo -e "${YELLOW}==> Cleaning up...${NC}"
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
}

trap cleanup EXIT

echo -e "${YELLOW}==> Starting OpenBao in dev mode...${NC}"
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${OPENBAO_PORT}:8200" \
    -e BAO_DEV_ROOT_TOKEN_ID="${OPENBAO_TOKEN}" \
    -e BAO_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
    --cap-add=IPC_LOCK \
    quay.io/openbao/openbao:latest

echo -e "${YELLOW}==> Waiting for OpenBao to be ready...${NC}"
for i in $(seq 1 30); do
    if curl -sf "${OPENBAO_ADDR}/v1/sys/health" > /dev/null 2>&1; then
        echo -e "${GREEN}OpenBao is ready!${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${RED}FAIL: OpenBao did not become ready in time${NC}"
        exit 1
    fi
    sleep 1
done

echo -e "${YELLOW}==> Enabling Transit secrets engine...${NC}"
curl -sf -X POST "${OPENBAO_ADDR}/v1/sys/mounts/transit" \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -d '{"type":"transit"}'
echo -e "${GREEN}Transit engine enabled${NC}"

echo -e "${YELLOW}==> Creating test keys...${NC}"
for key_spec in "test-ec-key:ecdsa-p256" "test-rsa-key:rsa-2048" "test-ed25519-key:ed25519"; do
    key_name="${key_spec%%:*}"
    key_type="${key_spec##*:}"
    curl -sf -X POST "${OPENBAO_ADDR}/v1/transit/keys/${key_name}" \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        -d "{\"type\":\"${key_type}\"}" > /dev/null
    echo -e "  ${GREEN}Created ${key_name} (${key_type})${NC}"
done

echo -e "${YELLOW}==> Building plugin...${NC}"
cd "${REPO_ROOT}"
CGO_ENABLED=0 go build -o bin/step-kms-openbao-plugin .
echo -e "${GREEN}Plugin built: bin/step-kms-openbao-plugin${NC}"

PLUGIN="${REPO_ROOT}/bin/step-kms-openbao-plugin"
export OPENBAO_ADDR OPENBAO_TOKEN
PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo -e "\n${YELLOW}==> ${name}${NC}"
    if "$@"; then
        echo -e "${GREEN}PASS: ${name}${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL: ${name}${NC}"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "============================================"
echo "  CLI Integration Tests"
echo "============================================"

run_test "Get EC P-256 public key" \
    "${PLUGIN}" key 'openbao:test-ec-key'

run_test "Get RSA 2048 public key" \
    "${PLUGIN}" key 'openbao:test-rsa-key'

run_test "Create new EC P-384 key" \
    "${PLUGIN}" create --kty EC --crv P384 'openbao:cli-test-ec384'

run_test "Create new RSA 4096 key" \
    "${PLUGIN}" create --kty RSA --size 4096 'openbao:cli-test-rsa4096'

echo "Hello OpenBao Integration Test" > /tmp/test-data.txt

run_test "Sign with EC key" \
    "${PLUGIN}" sign --in /tmp/test-data.txt 'openbao:test-ec-key'

run_test "Sign with RSA key" \
    "${PLUGIN}" sign --in /tmp/test-data.txt 'openbao:test-rsa-key'

# Verify the EC signature with openssl
echo -e "\n${YELLOW}==> Verify EC signature with OpenSSL${NC}"
"${PLUGIN}" key 'openbao:test-ec-key' > /tmp/ec-pub.pem
SIG=$("${PLUGIN}" sign --in /tmp/test-data.txt 'openbao:test-ec-key')
echo -n "${SIG}" | base64 -d > /tmp/sig.der
if openssl dgst -sha256 -verify /tmp/ec-pub.pem -signature /tmp/sig.der /tmp/test-data.txt 2>/dev/null; then
    echo -e "${GREEN}PASS: EC signature verified with OpenSSL${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL: EC signature verification failed${NC}"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "============================================"
echo "  Go Integration Tests"
echo "============================================"
echo ""

if go test -tags integration -v -count=1 ./kms/openbao/ -run TestIntegration; then
    echo -e "${GREEN}PASS: All Go integration tests passed${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL: Go integration tests failed${NC}"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "============================================"
echo "  Integration Test Summary"
echo "============================================"
echo -e "  ${GREEN}Passed: ${PASS}${NC}"
if [ "${FAIL}" -gt 0 ]; then
    echo -e "  ${RED}Failed: ${FAIL}${NC}"
    exit 1
else
    echo -e "  Failed: 0"
    echo -e "  ${GREEN}All tests PASSED!${NC}"
fi
