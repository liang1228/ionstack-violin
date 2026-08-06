#!/bin/bash
# Fix DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null

# Update and install
sudo apt-get update -qq 2>&1 | tail -3
sudo apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu 2>&1 | tail -10

echo "=== Verify ==="
which aarch64-linux-gnu-gcc && aarch64-linux-gnu-gcc --version | head -1 || echo "CROSS COMPILER NOT FOUND"
