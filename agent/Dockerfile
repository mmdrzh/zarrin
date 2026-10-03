FROM python:3.12-slim AS strongswan
# Debian's strongSwan ships no eap-mschapv2 (it needs MD4, which modern OpenSSL
# dropped), and native iOS/Windows IKEv2 username login requires it, so
# strongSwan is built here with its own MD4 plugin. 5.9.x, not 6.x: a 6.x
# charon's IKE_AUTH reply was dropped on Iranian mobile networks where 5.9.14
# with the same settings connects.
ARG STRONGSWAN_VERSION=5.9.14
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config bison flex gettext libgmp-dev libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" | tar -xj -C /tmp \
    && cd /tmp/strongswan-${STRONGSWAN_VERSION} \
    && ./configure --prefix=/usr --sysconfdir=/etc \
         --enable-eap-mschapv2 --enable-eap-identity --enable-md4 \
         --enable-openssl --enable-swanctl --enable-vici --disable-stroke --disable-scepclient \
    && make -j"$(nproc)" && make DESTDIR=/build install

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgmp10 libssl3 iptables iproute2 procps ca-certificates xl2tpd ppp openvpn \
    && rm -rf /var/lib/apt/lists/*
COPY --from=strongswan /build/ /
COPY --from=goacme/lego:v5.5.2 /lego /usr/local/bin/lego
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY strongswan.conf /etc/strongswan.d/zarrin.conf
COPY zarrin_agent ./zarrin_agent
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "zarrin_agent.main"]
