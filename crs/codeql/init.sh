#!/bin/bash

set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "$SCRIPT_DIR"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install CodeQL pack (downloads codeql/java-all and transitive deps into
# the CodeQL package cache so the analyze step can resolve library imports)
echo "Installing CodeQL pack..."
cd sink-queries
codeql pack install

echo "Initialization complete!"
