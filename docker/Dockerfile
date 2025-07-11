FROM rust

# install nightly rust
RUN rustup install nightly
RUN rustup default nightly

WORKDIR /workspace
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config build-essential ca-certificates iproute2
CMD ["bash"]