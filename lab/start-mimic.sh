#!/bin/sh
set -eu

certificate=/etc/mimic/.state/mimic-ca.pem
key=/etc/mimic/.state/mimic-ca-key.pem

if [ ! -s "$certificate" ] || [ ! -s "$key" ]; then
  echo "Creating the lab-only Mimic interception CA..."
  mimic init-ca -cert "$certificate" -key "$key"
fi

exec mimic daemon -config /etc/mimic/config.toml
