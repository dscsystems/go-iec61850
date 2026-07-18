# Bidirectional interop harness: builds libiec61850 and runs the Go
# interop tests against it in both directions.
#
#   docker build -f interop/Dockerfile -t go-iec61850-interop .
#   docker run --rm go-iec61850-interop
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git \
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
    && make -C "$WORK/libiec61850" -j"$(nproc)" examples

ENTRYPOINT ["bash", "interop/run.sh"]
