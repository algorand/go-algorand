FROM ubuntu:18.04
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y awscli jq ssh
#RUN adduser --uid $(grep jenkins /etc/passwd | awk -F: '{ print $3 }') ubuntu
RUN adduser --uid 111 ubuntu

