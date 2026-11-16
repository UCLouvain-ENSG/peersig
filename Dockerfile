# Collection server and relay. Build: docker build -t peersig .
# Server: docker run -v peersig:/data -p 8080:8080 peersig peersig-server --db /data/peersig.db serve --listen 0.0.0.0:8080
# Relay:  docker run -p 8081:8081 peersig peersig-relay --listen 0.0.0.0:8081 --gateway https://server.example
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p peersig-server -p peersig-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data peersig && mkdir /data && chown peersig /data
COPY --from=build /src/target/release/peersig-server /src/target/release/peersig-relay /usr/local/bin/
USER peersig
WORKDIR /data
EXPOSE 8080 8081
CMD ["peersig-server", "--db", "/data/peersig.db", "serve", "--listen", "0.0.0.0:8080"]
