#!/bin/bash -x
exec kill $(cat ${HOME}/phttpd.pid)
