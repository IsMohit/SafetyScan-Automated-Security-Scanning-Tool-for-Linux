#!/usr/bin/env bash
# install.sh - set up safetyscan as global command

set -e

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/safetyscan.sh"

DEST="/usr/local/bin/safetyscan"

sudo cp "$SCRIPT_PATH" "$DEST"
sudo chmod +x "$DEST"

echo "✅ safetyscan installed successfully!"
echo "You can now run it from anywhere using:"
echo "   safetyscan <project_path> --mode [sast|dast|both] [--start '<start_cmd>'] [--port <port>]"
