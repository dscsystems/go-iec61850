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
| Control: SBO-enhanced, CommandTermination±, LastApplError | ✓ | |

SBO with normal security is implemented on the server (`server/select.go`)
and covered by the unit tests; it has no interop assertion yet.

## Edition 2.1

This suite exercises the Edition 2 wire formats against libiec61850 v1.6,
which implements Edition 2 and the R-GOOSE/R-SV profiles. It is not an
Edition 2.1 conformance suite: it tests that the two stacks interoperate,
not that either is conformant.

That distinction matters for reading the Edition 2.1 work. Most of it is
*loader* changes — the SCL parser, the diagnostics, the control-block
objects the server now materialises — which interop cannot exercise at all,
because there is only one stack involved. Those are covered by
`scl/edition_test.go` and `server/cb_test.go` against the synthetic
`2007B4` fixture. The wire-format changes interop *can* cover — `smpMod`,
GOOSE state and timing semantics, time quality — are covered by
`goose/ed21_test.go` and `sv/ed21_test.go`.

Adding interop assertions for the wire-format changes is the obvious next
step and needs no harness change.
