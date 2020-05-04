FROM docker:19 as docker
FROM python:3.7

COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY *.yaml ./

RUN pip install mulecli

WORKDIR /root

CMD ["/bin/bash"]

