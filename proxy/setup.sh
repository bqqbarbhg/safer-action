#!/usr/bin/env bash
set -e
set -o pipefail
set -x

cd /proxy
go build proxy.go
