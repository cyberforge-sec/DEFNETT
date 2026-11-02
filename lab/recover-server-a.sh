#!/bin/sh
set -eu

curl --fail --silent --show-error --request POST \
    http://127.0.0.1:8090/v1/lab/recover/server-a
printf '\n'
