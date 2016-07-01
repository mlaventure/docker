FROM armhf/debian:jessie

# allow replacing httpredir mirror
ARG APT_MIRROR=httpredir.debian.org
RUN sed -i s/httpredir.debian.org/$APT_MIRROR/g /etc/apt/sources.list

RUN apt-get update && apt-get install -y apparmor bash-completion btrfs-tools build-essential curl ca-certificates debhelper dh-apparmor dh-systemd git libapparmor-dev libdevmapper-dev libltdl-dev libsqlite3-dev libsystemd-journal-dev pkg-config --no-install-recommends && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION 1.6.2
RUN curl -fSL "https://storage.googleapis.com/golang/go${GO_VERSION}.linux-armv6l.tar.gz" | tar xzC /usr/local
ENV PATH $PATH:/usr/local/go/bin

# install seccomp: the version shipped in trusty is too old
ENV SECCOMP_VERSION 2.3.1
RUN set -x \
        && export SECCOMP_PATH="$(mktemp -d)" \
        && curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v${SECCOMP_VERSION}/libseccomp-${SECCOMP_VERSION}.tar.gz" \
                | tar -xzC "$SECCOMP_PATH" --strip-components=1 \
        && ( \
                cd "$SECCOMP_PATH" \
                && ./configure --prefix=/usr/local \
                && make \
                && make install \
                && ldconfig \
        ) \
        && rm -rf "$SECCOMP_PATH"

ENV AUTO_GOPATH 1
