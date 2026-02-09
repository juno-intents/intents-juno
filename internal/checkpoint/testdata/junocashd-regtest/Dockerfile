FROM ubuntu:22.04

ARG JUNOCASH_VERSION=0.9.8
ARG JUNOCASH_LINUX64_SHA256=67aca81b97644525aaa997024b15815202a0ea68f378d9d0213b4a3cb2ed6960

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar libnuma1 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/junocash.tar.gz "https://github.com/juno-cash/junocash/releases/download/v${JUNOCASH_VERSION}/junocash-${JUNOCASH_VERSION}-linux64.tar.gz" \
  && echo "${JUNOCASH_LINUX64_SHA256}  /tmp/junocash.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/junocash.tar.gz -C /opt \
  && ln -s "/opt/junocash-${JUNOCASH_VERSION}/bin/junocashd" /usr/local/bin/junocashd \
  && ln -s "/opt/junocash-${JUNOCASH_VERSION}/bin/junocash-cli" /usr/local/bin/junocash-cli \
  && rm /tmp/junocash.tar.gz

RUN useradd -m -u 10001 junocash
USER junocash

EXPOSE 18232

ENTRYPOINT ["junocashd"]
CMD ["-regtest","-printtoconsole","-listen=0","-rpcuser=rpcuser","-rpcpassword=rpcpass","-rpcallowip=0.0.0.0/0","-rpcbind=0.0.0.0","-rpcport=18232"]
