#!/usr/bin/env bash
set -euo pipefail

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Resolve version
VERSION="${GREYWALL_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/GreyhavenHQ/greywall/releases/latest" | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
fi

# Download and install binary
FILENAME="greywall_${VERSION}_$(uname -s)_${ARCH}.tar.gz"
URL="https://github.com/GreyhavenHQ/greywall/releases/download/v${VERSION}/${FILENAME}"
echo "Installing greywall v${VERSION} from ${URL}"

TMP=$(mktemp -d)
curl -fsSL "$URL" -o "$TMP/greywall.tar.gz"
tar -xz -C "$TMP" -f "$TMP/greywall.tar.gz"
sudo mv "$TMP/greywall" /usr/local/bin/greywall
sudo chmod +x /usr/local/bin/greywall
rm -rf "$TMP"

# Write config
CONFIG_DIR="$HOME/.config/greywall"
mkdir -p "$CONFIG_DIR"

# Build allowRead from allow-network (passed as domains, mapped to network config)
# Build denyRead array from GREYWALL_DENY_READ
DENY_READ_JSON="[]"
if [ -n "${GREYWALL_DENY_READ:-}" ]; then
  DENY_READ_JSON=$(echo "$GREYWALL_DENY_READ" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | jq -R . | jq -s .)
fi

# Build allowed domains list for network
ALLOW_NETWORK_JSON="[]"
if [ -n "${GREYWALL_ALLOW_NETWORK:-}" ]; then
  ALLOW_NETWORK_JSON=$(echo "$GREYWALL_ALLOW_NETWORK" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | jq -R . | jq -s .)
fi

cat > "$CONFIG_DIR/greywall.json" <<EOF
{
  "filesystem": {
    "denyRead": $DENY_READ_JSON
  },
  "network": {
    "allow": $ALLOW_NETWORK_JSON
  }
}
EOF

echo "Greywall configured at $CONFIG_DIR/greywall.json"
greywall --version
