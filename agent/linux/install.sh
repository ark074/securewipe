#!/bin/bash
set -e
echo "Installing SecureWipe agent (Linux)"
sudo mkdir -p /etc/securewipe /var/lib/securewipe /usr/local/bin
# copy binary and scripts (operator must copy files from package manually)
echo "Copy securewipe_agent binary to /usr/local/bin and config to /etc/securewipe/config.yaml"
echo "Enable and start systemd service: sudo systemctl enable --now securewipe-agent"
