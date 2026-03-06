#!/bin/sh
# setup-openbao.sh
# Initializes the OpenBao Transit secrets engine with test keys and policies.

set -e

echo "==> Waiting for OpenBao to be ready..."
until bao status -address="${BAO_ADDR}" > /dev/null 2>&1; do
  sleep 1
done

echo "==> Enabling Transit secrets engine..."
bao secrets enable -address="${BAO_ADDR}" transit || echo "Transit engine may already be enabled"

echo "==> Creating ECDSA P-256 key: test-ec-key..."
bao write -address="${BAO_ADDR}" transit/keys/test-ec-key type=ecdsa-p256

echo "==> Creating RSA 2048 key: test-rsa-key..."
bao write -address="${BAO_ADDR}" transit/keys/test-rsa-key type=rsa-2048

echo "==> Creating Transit policy..."
bao policy write -address="${BAO_ADDR}" transit-policy - <<EOF
path "transit/keys/*" {
  capabilities = ["create", "read", "update", "list"]
}
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/verify/*" {
  capabilities = ["create", "update"]
}
path "transit/export/public-key/*" {
  capabilities = ["read"]
}
EOF

echo "==> OpenBao Transit setup complete!"
echo "    Keys: test-ec-key (ecdsa-p256), test-rsa-key (rsa-2048)"
echo "    Policy: transit-policy"
