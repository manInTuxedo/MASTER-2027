# Builds upstream OpenSSH from the official source tarball, so the running version is exactly the one
# requested. (Distro packages backport security fixes without changing the version number, which would
# make the NVD ground truth wrong for this lab.)
FROM debian:bookworm-slim

ARG OPENSSH_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential zlib1g-dev libssl-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSL -o openssh.tar.gz "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" \
 && tar xzf openssh.tar.gz --strip-components=1 \
 && ./configure --prefix=/opt/openssh --sysconfdir=/opt/openssh/etc \
      --with-privsep-path=/var/empty --without-pam --without-zlib-version-check \
 && make -j"$(nproc)" \
 && make install-nokeys \
 && cd / && rm -rf /src

RUN useradd --system --home-dir /var/empty --shell /usr/sbin/nologin sshd \
 && mkdir -p /var/empty && chmod 755 /var/empty \
 && /opt/openssh/bin/ssh-keygen -q -t ed25519 -N "" -f /opt/openssh/etc/ssh_host_ed25519_key \
 && printf 'Port 22\nHostKey /opt/openssh/etc/ssh_host_ed25519_key\nPasswordAuthentication no\n' \
      > /opt/openssh/etc/sshd_config

EXPOSE 22
CMD ["/opt/openssh/sbin/sshd", "-D", "-e", "-f", "/opt/openssh/etc/sshd_config"]
