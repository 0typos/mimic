#!/bin/sh
set -eu

certificate=/etc/mimic/.state/mimic-ca.pem
key=/etc/mimic/.state/mimic-ca-key.pem

if [ ! -s "$certificate" ] || [ ! -s "$key" ]; then
  echo "Creating the lab-only Mimic interception CA..."
  mimic init-ca -cert "$certificate" -key "$key"
fi

# The daemon deliberately refuses non-loopback control binds. This lab-only
# forwarder lets a host-local Caido plugin reach that control endpoint through
# a Docker port published exclusively on 127.0.0.1.
/usr/local/bin/lab-origin tcp-forward 0.0.0.0:9091 127.0.0.1:9090 &

exec mimic daemon -config /etc/mimic/config.toml
