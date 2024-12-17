#!/usr/bin/env bash

#
# Copyright (c) 2024 Gaba <gabriel.correasb@protonmail.com>
#

MAIL_TO="admin@example.com"
SCRIPT_DIR="$(cd "$dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="${SCRIPT_DIR}/ids.py"

OUTPUT=$("PYTHON_SCRIPT")

if echo "$OUTPUT" | grep -q "Suspicious dctivity detected"; then
    echo "$OUTPUT" | mail -s "IDS Alert: Suspicious SSH Activity" "$MAIL_TO"
fi