FROM rust:1.82 as builder
WORKDIR /usr/src/app
COPY backend ./backend
WORKDIR /usr/src/app/backend
RUN cargo build --release
FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/backend/target/release/securewipe_agent /usr/local/bin/securewipe_agent
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/securewipe_agent"]
