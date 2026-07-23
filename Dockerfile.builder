# Debian package builder for keriguard
# Based on Ubuntu 22.04 with Python 3.13 from deadsnakes PPA
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add deadsnakes PPA for Python 3.13
RUN add-apt-repository ppa:deadsnakes/ppa && apt-get update

# Install build dependencies
RUN apt-get install -y \
    debhelper \
    devscripts \
    dh-virtualenv \
    python3.13 \
    python3.13-dev \
    python3.13-venv \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    build-essential \
    git \
    libsodium-dev \
    libdbus-1-dev \
    dpkg-dev \
    fakeroot \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies for testing
RUN apt-get update && apt-get install -y \
    wireguard-tools \
    dbus \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Default command
CMD ["/bin/bash"]
