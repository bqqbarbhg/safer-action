FROM golang:bullseye

RUN apt-get update && apt-get install -y dos2unix
COPY setup.sh /
COPY config.json proxy.go /proxy/
RUN dos2unix /setup.sh && chmod +x /setup.sh
RUN /setup.sh

WORKDIR /proxy
USER proxy
ENTRYPOINT ["./proxy"]
