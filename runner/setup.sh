#!/usr/bin/env bash

set -e
set -x
set -o pipefail

mkdir -p /home/runner
cd /home/runner

NAME=actions-runner-${ARG_OS}-${ARG_ARCH}-${ARG_VERSION}

curl -o ${NAME}.tar.gz -L https://github.com/actions/runner/releases/download/v${ARG_VERSION}/${NAME}.tar.gz
sha256sum ${NAME}.tar.gz
echo "${ARG_CHECKSUM}  ${NAME}.tar.gz" | sha256sum -c
tar -zxf ${NAME}.tar.gz
rm -f ${NAME}.tar.gz
./bin/installdependencies.sh
