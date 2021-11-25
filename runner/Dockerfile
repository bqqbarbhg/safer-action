ARG ARG_ARCH_PREFIX=""

FROM ${ARG_ARCH_PREFIX}debian:bullseye

ARG ARG_OS="linux"
ARG ARG_ARCH="x64"
ARG ARG_VERSION="2.284.0"
ARG ARG_CHECKSUM="1ddfd7bbd3f2b8f5684a7d88d6ecb6de3cb2281a2a359543a018cc6e177067fc"

RUN groupadd -g 1001 runner && useradd -r -u 1001 -g runner runner

RUN apt-get update && apt-get install -y curl dos2unix

COPY setup.sh /
RUN dos2unix /setup.sh && chmod +x /setup.sh
RUN /setup.sh

COPY start.sh /
RUN dos2unix /start.sh && chmod +x /start.sh

COPY user-setup.sh /
RUN dos2unix /user-setup.sh && chmod +x /user-setup.sh
RUN /user-setup.sh

USER runner
ENTRYPOINT ["bash", "/start.sh"]
