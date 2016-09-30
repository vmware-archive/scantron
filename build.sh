#!/bin/bash

set -e
set -x

go install github.com/jteeuwen/go-bindata/go-bindata

GOOS=linux GOARCH=amd64 go build -o data/proc_scan ./cmd/proc_scan

go-bindata -o proc_scan.go -pkg scantron data

go build -o scantron ./cmd/scantron
