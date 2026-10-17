# Containerized reproducible build environment for ITSA Network OS Live Image
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

# Install live-build toolchain and ISO creation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    live-build \
    debootstrap \
    squashfs-tools \
    xorriso \
    syslinux \
    syslinux-utils \
    isolinux \
    dosfstools \
    mtools \
    ca-certificates \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash", "/workspace/scripts/build_live_iso.sh"]
