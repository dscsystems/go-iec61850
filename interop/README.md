# Interop harness

Bidirectional interoperability tests against
[libiec61850](https://github.com/mz-automation/libiec61850):

1. our `client` against the C `server_example_basic_io`
2. the C `client_example1` and control example against our `server`

The Go interop tests are guarded by environment variables and skipped in
the normal `go test ./...` run, so a checkout without a C toolchain stays
green. This harness builds libiec61850 and supplies those variables.

## Run locally

```sh
bash interop/run.sh          # clones + builds libiec61850 v1.6, runs both directions
LIBIEC61850_REF=v1.5 bash interop/run.sh
```

The build is cached under `.interop-work/` (git-ignored).

## Run in Docker

```sh
docker build -f interop/Dockerfile -t go-iec61850-interop .
docker run --rm go-iec61850-interop
```

## CI

`.github/workflows/interop.yml` runs `interop/run.sh` on every push and
pull request.

## Coverage

| Feature | our client -> C server | C client -> our server |
|---------|:----------------------:|:----------------------:|
| Associate / Identify | ✓ | ✓ |
| Browse (getNameList) | ✓ | ✓ |
| Read / Write | ✓ | ✓ |
| GetVariableAccessAttributes | ✓ | ✓ |
| Datasets | ✓ | ✓ |
| Reporting (URCB, GI/dchg/integrity) | ✓ | ✓ |
| Control (direct-normal, direct-enhanced) | ✓ | ✓ |

SBO-with-normal-security select reservation is not yet implemented on the
server side.
