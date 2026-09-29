# Bidirectional interop harness: builds libiec61850 and runs the Go
# interop tests against it in both directions.
#
#   docker build -f interop/Dockerfile -t go-iec61850-interop .
#   docker run --rm go-iec61850-interop
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake curl git libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Cache module downloads.
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .

# Pre-build libiec61850 into the image so `docker run` is fast.
ENV WORK=/opt/interop-work
RUN mkdir -p "$WORK" \
    && git clone --depth 1 --branch v1.6 https://github.com/mz-automation/libiec61850.git "$WORK/libiec61850" \
    && make -C "$WORK/libiec61850" -j"$(nproc)" examples \
    && make -C "$WORK/libiec61850/examples/server_example_logging" \
    && make -C "$WORK/libiec61850/examples/iec61850_client_example_log"
# The security build (mbedtls, R-GOOSE/R-SV, TLS); run.sh builds the peer.
RUN git clone --depth 1 --branch v1.6 https://github.com/mz-automation/libiec61850.git "$WORK/libiec61850-sec" \
    && curl -sSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.0.tar.gz \
       | tar xz -C "$WORK/libiec61850-sec/third_party/mbedtls" \
    && cmake -S "$WORK/libiec61850-sec" -B "$WORK/libiec61850-sec/cbuild" -DBUILD_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build "$WORK/libiec61850-sec/cbuild" -j"$(nproc)"

ENTRYPOINT ["bash", "interop/run.sh"]
