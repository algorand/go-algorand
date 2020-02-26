# Note that we're installing `awscli` from pip rather than from the apt repository because of
# the following error message:
#
# upload failed: pkg/2.0.63803/build_status_dev_2.0.63803.asc.gz to s3://ben-test-2.0.3/dev/2.0.63803/build_status_dev_2.0.63803.asc.gz seek() takes 2 positional arguments but 3 were given
#
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869194
# https://github.com/boto/s3transfer/pull/102

FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y jq git python python-pip ssh && \
    pip install awscli

