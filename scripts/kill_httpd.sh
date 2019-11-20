#!/usr/bin/env bash
set -x
exec kill $(cat ${HOME}/phttpd.pid)
