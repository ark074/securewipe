#!/bin/bash
set -e
mkdir -p demo
fallocate -l 1G demo/test.img
echo "Loopback image created at demo/test.img"
echo "Associate with: sudo losetup -fP demo/test.img"
