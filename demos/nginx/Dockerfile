# nginx on QudoSSL Community — post-quantum TLS 1.3 termination.
#
# Builds QudoSSL from THIS repository's source as a STANDARD build (FIPS=no:
# no FIPS module; ML-KEM and ML-DSA run in the default provider), then builds
# nginx against it. Build context is the repository root:
#
#   docker compose -f demos/nginx/compose.yaml up --build -d
#
# First build takes roughly 10-20 minutes (OpenSSL + qudo-pqc-lib + nginx).

ARG NGINX_VERSION=1.28.0
ARG NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a

# --- build: QudoSSL, then nginx ---------------------------------------------
FROM debian:12 AS build
ARG NGINX_VERSION
ARG NGINX_SHA256
ARG QUDOSSL_PREFIX=/opt/qudossl

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake perl curl ca-certificates libpcre2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Same commands as the README's "Build and install (standard build)" section.
# The RPATH keeps nginx and the CLI on QudoSSL's libssl rather than the
# distribution's.
RUN make -C build all FIPS=no PREFIX="$QUDOSSL_PREFIX" \
        OPENSSL_EXTRA_FLAGS="-Wl,-rpath,$QUDOSSL_PREFIX/lib" \
 && make -C build install_sw PREFIX="$QUDOSSL_PREFIX" \
 && make -C openssl install_ssldirs

WORKDIR /build
RUN curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
 && echo "${NGINX_SHA256}  nginx-${NGINX_VERSION}.tar.gz" | sha256sum -c - \
 && tar xf "nginx-${NGINX_VERSION}.tar.gz" \
 && cd "nginx-${NGINX_VERSION}" \
 && ./configure --prefix=/usr/local/nginx --with-http_ssl_module --with-http_v2_module \
        --with-cc-opt="-I$QUDOSSL_PREFIX/include" \
        --with-ld-opt="-L$QUDOSSL_PREFIX/lib -Wl,-rpath,$QUDOSSL_PREFIX/lib" \
 && make -j"$(nproc)" && make install

# Demo-only self-signed certificate: an ordinary RSA certificate. The key
# exchange is post-quantum; the certificate does not need to change.
RUN mkdir -p /usr/local/nginx/certs \
 && "$QUDOSSL_PREFIX/bin/openssl" req -x509 -new -noenc -newkey rsa:3072 \
      -keyout /usr/local/nginx/certs/server.key \
      -out    /usr/local/nginx/certs/server.crt \
      -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"

# --- runtime ----------------------------------------------------------------
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcre2-8-0 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/qudossl /opt/qudossl
COPY --from=build /usr/local/nginx /usr/local/nginx
COPY demos/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf

# No OPENSSL_CONF: QudoSSL reads the openssl.cnf that install_ssldirs put in
# /opt/qudossl/ssl, and the default provider loads without any configuration.
ENV PATH=/opt/qudossl/bin:$PATH

EXPOSE 8443
CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
