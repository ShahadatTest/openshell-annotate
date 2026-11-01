#!/usr/bin/env bash
# @openshell egress registry.npmjs.org:443 reason="npm install" bin=/usr/local/bin/node access=read-only
# @openshell fs read /etc/ssl/certs reason="CA bundle"
npm install --no-audit
