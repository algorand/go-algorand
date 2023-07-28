FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install git python3 python3-pip -y && \
    pip3 install awscli boto3

WORKDIR /root

CMD ["/bin/bash"]

