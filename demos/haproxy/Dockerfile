# HAProxy on QudoSSL Community — post-quantum TLS 1.3 termination.
#
# Builds QudoSSL from THIS repository's source as a STANDARD build (FIPS=no:
# no FIPS module; ML-KEM and ML-DSA run in the default provider), then builds
# HAProxy against it. Build context is the repository root:
#
#   docker compose -f demos/haproxy/compose.yaml up --build -d
#
# First build takes roughly 10-20 minutes (OpenSSL + qudo-pqc-lib + HAProxy).

# --- build: QudoSSL, then HAProxy -------------------------------------------
FROM debian:12 AS build
ARG QUDOSSL_PREFIX=/opt/qudossl

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake perl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Same commands as the README's "Build and install (standard build)" section.
# The RPATH keeps HAProxy and the CLI on QudoSSL's libssl rather than the
# distribution's.
RUN make -C build all FIPS=no PREFIX="$QUDOSSL_PREFIX" \
        OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib" \
 && make -C build install_sw PREFIX="$QUDOSSL_PREFIX" \
 && make -C openssl install_ssldirs

# HAProxy 3.0 LTS. The checksum is the one haproxy.org publishes alongside the
# release (haproxy-<version>.tar.gz.sha256).
ARG HAPROXY_BRANCH=3.0
ARG HAPROXY_VERSION=3.0.30
ARG HAPROXY_SHA256=a7c594a1985936890737219ae2d7c3769346a92a2f536522b8b3abc540d7a608

WORKDIR /build
RUN curl -fsSLO "https://www.haproxy.org/download/${HAPROXY_BRANCH}/src/haproxy-${HAPROXY_VERSION}.tar.gz" \
 && echo "${HAPROXY_SHA256}  haproxy-${HAPROXY_VERSION}.tar.gz" | sha256sum -c - \
 && tar xf "haproxy-${HAPROXY_VERSION}.tar.gz" \
 && cd "haproxy-${HAPROXY_VERSION}" \
 && make -j"$(nproc)" TARGET=linux-glibc USE_OPENSSL=1 \
        SSL_INC="$QUDOSSL_PREFIX/include" SSL_LIB="$QUDOSSL_PREFIX/lib" \
        LDFLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib" \
 && make install-bin PREFIX=/usr/local

# Demo-only self-signed certificate: an ordinary RSA certificate. The key
# exchange is post-quantum; the certificate does not need to change. HAProxy
# reads the certificate and key from one PEM file.
RUN mkdir -p /usr/local/etc/haproxy/certs \
 && cd /usr/local/etc/haproxy/certs \
 && "$QUDOSSL_PREFIX/bin/openssl" req -x509 -new -noenc -newkey rsa:3072 \
      -keyout server.key -out server.crt -days 365 \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
 && cat server.crt server.key > server.pem && rm server.key

# --- runtime ----------------------------------------------------------------
FROM debian:12-slim

COPY --from=build /opt/qudossl /opt/qudossl
COPY --from=build /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=build /usr/local/etc/haproxy/certs /usr/local/etc/haproxy/certs
COPY demos/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

# No OPENSSL_CONF: QudoSSL reads the openssl.cnf that install_ssldirs put in
# /opt/qudossl/ssl, and the default provider loads without any configuration.
ENV PATH=/opt/qudossl/bin:$PATH

EXPOSE 9443
CMD ["/usr/local/sbin/haproxy", "-W", "-db", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
