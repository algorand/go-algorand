#!/usr/bin/env bash

set -ex
exec kill $(cat "$MULE_TEST_DIR/phttpd.pid")

