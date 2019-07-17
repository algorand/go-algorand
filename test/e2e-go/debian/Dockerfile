#FROM golang:1.11-alpine AS build
#FROM ubuntu:18.04
FROM debian:stable
RUN \
apt-get update && \
#apt-get install -y gnupg-curl && \
apt-get update && \
apt-get install -y apt-transport-https && \
apt-get update && \
apt-get install -y gnupg2 curl software-properties-common && \
apt-key adv --fetch-keys https://releases.algorand.com/key.pub && \
add-apt-repository "deb https://releases.algorand.com/deb/ stable main" && \
apt-get update && \
apt-get install -y apt-transport-https && \
apt-get update && \
apt-get install -y algorand && \
apt-get install -y expect 
ENV LANG en_US.utf8
