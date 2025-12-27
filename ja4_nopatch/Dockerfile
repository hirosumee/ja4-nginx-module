FROM alpine:3.18

ARG NGINX_VERSION=1.25.0
ARG OPENSSL_VERSION=3.2.1

RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    wget \
    perl-dev \
    linux-headers

WORKDIR /tmp

# 1. Download OpenSSL (Standard)
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar -zxf openssl-${OPENSSL_VERSION}.tar.gz

# 2. Download Nginx (Standard)
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz

# 3. Copy our No-Patch Module
COPY . /tmp/ja4_nopatch

# 4. Build Nginx with our module
WORKDIR /tmp/nginx-${NGINX_VERSION}

# Note: We point --add-module to our copied directory
# We use standard OpenSSL
RUN ./configure \
    --with-openssl=/tmp/openssl-${OPENSSL_VERSION} \
    --with-debug \
    --with-compat \
    --add-module=/tmp/ja4_nopatch \
    --with-http_ssl_module \
    --prefix=/etc/nginx \
    && make \
    && make install

# Generate self-signed certificate
RUN openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem -days 365 -nodes -subj '/CN=localhost'

# Cleanup
WORKDIR /
RUN rm -rf /tmp/*


# Logs
RUN ln -sf /dev/stdout /etc/nginx/logs/access.log && \
    ln -sf /dev/stderr /etc/nginx/logs/error.log

# Verify module loading
RUN /etc/nginx/sbin/nginx -V

CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
