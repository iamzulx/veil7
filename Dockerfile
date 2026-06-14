# veil7 Docker image — multi-stage, minimal
# Build: docker build -t veil7 .
# Run: docker run --rm veil7 sign "hello"

# Stage 1: Build
FROM rust:1.95-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked
RUN strip target/release/veil7

# Stage 2: Runtime (minimal)
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/veil7 /usr/local/bin/veil7
ENTRYPOINT ["veil7"]
