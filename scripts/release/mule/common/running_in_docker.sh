#!/usr/bin/env bash

set -eo pipefail

# Sometimes we'll need to know if a process is running inside a docker container.
#
# For example, when signing build artifacts, the location of the gpg keys should default to the home directory
# of the user running the script when executing the shell script directly.
#
# For the same use case, the location of the gpg keys will default to `/root` if running a `mule` task.
#
# https://tuhrig.de/how-to-know-you-are-inside-a-docker-container/
awk -F/ '$2 == "docker"' /proc/self/cgroup | read -r

