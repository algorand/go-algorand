FROM debian:stable
RUN \
apt-get update && \
apt-get install -y apt-transport-https && \
apt-get install -y gnupg2 curl software-properties-common && \
apt-key adv --fetch-keys https://releases.algorand.com/key.pub && \
add-apt-repository "deb https://releases.algorand.com/deb/ stable main" && \
apt-get install -y apt-transport-https && \
apt-get install -y algorand && \
apt-get install -y expect && \
apt-get update
ENV LANG en_US.utf8
