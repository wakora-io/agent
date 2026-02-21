FROM debian:12-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates procps && rm -rf /var/lib/apt/lists/*
COPY wakora /usr/local/bin/wakora
ENTRYPOINT ["/usr/local/bin/wakora"]
