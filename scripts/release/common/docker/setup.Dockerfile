# Note that we're installing `awscli` from pip rather than from the apt repository because of
# the following error message:
#
# upload failed: pkg/2.0.63803/build_status_dev_2.0.63803.asc.gz to s3://{upload_location}/build_status_dev_2.0.63803.asc.gz seek() takes 2 positional arguments but 3 were given
#
# Note that the error only seems to occur when there is a file to upload with zero bytes,
# but just to be safe we'll still use pip to download and install.
#
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869194
# https://github.com/boto/s3transfer/pull/102

FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y jq git python python-pip python3-boto3 ssh && \
    pip install awscli

