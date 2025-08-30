# 7_PQC_Proxy_Deployment/Dockerfile
# Conceptual Multi-stage Dockerfile for Nginx with OpenSSL 3 + OQS Provider

# Stage 1: Builder (Build OQS components)
FROM ubuntu:22.04 AS builder
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake git ninja-build libssl-dev wget curl

# 1. Build liboqs (Core PQC algorithms implementation)
WORKDIR /build/liboqs
# Use specific tags/commits for production stability
RUN git clone https://github.com/open-quantum-safe/liboqs.git . && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/liboqs .. && \
    ninja && ninja install

# 2. Build OQS Provider for OpenSSL 3
# This dynamically loadable module integrates liboqs with OpenSSL 3.
WORKDIR /build/oqs-provider
RUN git clone https://github.com/open-quantum-safe/oqs-provider.git . && \
    mkdir build && cd build && \
    # Assumes system OpenSSL 3 (/usr) and links against the built liboqs
    cmake -DOPENSSL_ROOT_DIR=/usr -DLIBOQS_ROOT_DIR=/opt/liboqs .. && \
    make && make install

# Stage 2: Runtime (Using a standard Nginx image)
# NOTE: Standard nginx:alpine often uses LibreSSL or older OpenSSL. 
# For robust OpenSSL 3 support, use an Ubuntu or Debian based Nginx image.
FROM nginx:1.25-bookworm # Bookworm (Debian 12) typically ships with OpenSSL 3

# Copy OQS libraries and the provider module
COPY --from=builder /opt/liboqs/lib/liboqs.so* /usr/local/lib/
# Path might vary slightly based on the build system (lib vs lib64)
# Adjust the path based on the 'make install' output from the builder stage
# Example path used here; verify the actual install location in your build
# Note: oqs-provider often installs to /usr/local/lib/ossl-modules/
COPY --from=builder /usr/local/lib/ossl-modules/oqsprovider.so /usr/local/lib/ossl-modules/oqsprovider.so

# Update linker cache so Nginx can find liboqs.so
RUN ldconfig

# Copy configuration files (assuming they are in the context directory during build)
# COPY nginx.conf /etc/nginx/nginx.conf
# COPY openssl.cnf /etc/ssl/openssl.cnf

HEALTHCHECK CMD curl --fail http://localhost/healthz || exit 1

# Disclaimer: This proxy is intended for interoperability testing, NOT for protecting sensitive production traffic until thoroughly vetted.