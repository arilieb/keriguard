#!/bin/bash
# KERIGuard Permission Fix Script
# Ensures /usr/local/var/keri is owned by keriguard:keriguard
# This allows the keriguard service to access files created by root

set -e

KERI_DIR="/usr/local/var/keri"

if [ -d "$KERI_DIR" ]; then
    chown -R keriguard:keriguard "$KERI_DIR"
fi

exit 0
