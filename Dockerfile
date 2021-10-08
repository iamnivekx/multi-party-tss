FROM rust:1.54 as builder

RUN rustup toolchain install nightly-2021-08-31 \
    && rustup default nightly-2021-08-31

# 1. Create a new empty shell project
RUN USER=root cargo new --bin tss
WORKDIR ./tss

# 2. Copy our manifests
COPY Cargo.toml Cargo.lock ./

# 3. Build only the dependencies to cache them
RUN cargo build --release
RUN rm -rf ./src

# 4. Now that the dependency is built, copy your source code
COPY . .

# 5. Build for release.
RUN rm ./target/release/deps/tss*
RUN cargo build --release

FROM debian:buster-slim

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tss/target/release/tss /usr/local/bin/tss

CMD ["tss"]