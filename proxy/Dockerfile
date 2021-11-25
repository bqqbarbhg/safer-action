FROM golang:bullseye

RUN apt-get update && apt-get install -y dos2unix curl
COPY setup.sh /
COPY config.json proxy.go /proxy/
RUN dos2unix /setup.sh
RUN /setup.sh

WORKDIR /proxy
USER proxy
ENTRYPOINT ["./proxy"]
