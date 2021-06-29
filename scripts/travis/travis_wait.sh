#!/usr/bin/env bash
#
# Copyright (c) 2016 Travis CI GmbH <contact@travis-ci.org>
#
# SPDX-License-Identifier: MIT
#
# Based on the travis-ci/travis-build

ANSI_RED="\033[31;1m"
ANSI_GREEN="\033[32;1m"
ANSI_RESET="\033[0m"

travis_jigger() {
  # helper method for travis_wait()
  local cmd_pid=$1
  shift
  local timeout=$1 # in minutes
  shift
  local count=0

  # clear the line
  echo -e "\n"

  while [ $count -lt $timeout ]; do
    count=$(($count + 1))
    echo -ne "Still running ($count of $timeout): $@\r"
    sleep 60
  done

  echo -e "\n${ANSI_RED}Timeout (${timeout} minutes) reached. Terminating \"$@\"${ANSI_RESET}\n"
  kill -9 $cmd_pid
}

travis_wait() {
  local timeout=$1

  if [[ $timeout =~ ^[0-9]+$ ]]; then
    # looks like an integer, so we assume it's a timeout
    shift
  else
    # default value
    timeout=20
  fi

  local cmd="$@"
  local log_file=travis_wait_$$.log

  $cmd &>$log_file &
  local cmd_pid=$!

  travis_jigger $! $timeout $cmd &
  local jigger_pid=$!
  local result

  {
    wait $cmd_pid 2>/dev/null
    result=$?
    ps -p$jigger_pid &>/dev/null && kill $jigger_pid
  } || return 1

  if [ $result -eq 0 ]; then
    echo -e "\n${ANSI_GREEN}The command \"$cmd\" exited with $result.${ANSI_RESET}\n${ANSI_GREEN}Log:${ANSI_RESET}\n"
    tail -n 200 "${log_file}"
  else
    echo -e "\n${ANSI_RED}The command \"$cmd\" exited with $result.${ANSI_RESET}\n${ANSI_GREEN}Log:${ANSI_RESET}\n"
    cat "${log_file}"
  fi
  rm -f "${log_file}"
  return $result
}

travis_wait "$@"
