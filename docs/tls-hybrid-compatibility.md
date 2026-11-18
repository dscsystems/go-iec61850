# TLS and ML-KEM hybrid compatibility

Verified with Go 1.25.0, 1.26.11 and 1.27.4 on Linux amd64. The standard `iec62351` transport
supports TLS 1.2 and TLS 1.3 with mutual certificate authentication.
`Options.TLS13Only` raises the minimum to TLS 1.3. `Options.NativeMode`
restricts the connection to TLS 1.2 and rejects `TLS13Only`.

The default `Curves` list is P-256, P-384 and P-521. This overrides Go's
standard-library group defaults: ML-KEM hybrid key exchange is **not
negotiated by the library's default profile**.

Verified using actual handshakes, negotiated protocol/group assertions on
both endpoints, and an encrypted application-data round trip. Each refusal
below is checked against the server's reason for it (no shared key
exchange, no shared cipher suite, no shared version, or an untrusted
certificate), not just against any failure:

- TLS 1.2 and TLS 1.3 work with each of P-256, P-384 and P-521, in both roles.
- A TLS 1.3 peer offering a hybrid plus P-256 connects using classical P-256.
- A TLS 1.3 hybrid-only peer fails against the default profile, in both roles.
- Profile clients and servers configured as below negotiate
  X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 under TLS 1.3,
  and still refuse a peer whose certificate chains to another CA, in both
  roles.
- Hybrid-only configurations fail under TLS 1.2: the groups are TLS 1.3
  key exchanges, defined by the IETF draft
  [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
  and registered in the IANA
  [TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
  registry.
- Native-mode profile clients and servers negotiate TLS 1.2, and refuse a
  TLS 1.3-only peer in both roles.

## Explicit configuration

After calling `iec62351.ClientConfig` or `iec62351.ServerConfig` without
`NativeMode`, and before using the configuration for any connections,
applications can set:

```go
cfg.MinVersion = tls.VersionTLS13
cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
```

Apply compatible settings at both ends. This requires hybrid negotiation;
adding `tls.CurveP256` permits classical fallback. The configuration retains
the profile's certificate verification.

Do not apply this to a `NativeMode` configuration: native mode caps the
connection at TLS 1.2, so a TLS 1.3 minimum leaves no version both bounds
allow and every handshake fails.

Each configuration holds its own copy of `iec62351.Curves` and
`iec62351.CipherSuites`, so changing those variables affects only
configurations built afterwards.

X25519MLKEM768 is available since Go 1.24; the module's minimum Go 1.25
supports it and exposes `ConnectionState.CurveID`. SecP256r1MLKEM768 and
SecP384r1MLKEM1024 require Go 1.26 or later, and the `tlssecpmlkem=1`
setting when the application's `go.mod` declares a `go` version below
1.26: the toolchain then defaults it to 0, and Go 1.26 drops the two
groups even from an explicit `CurvePreferences`. Set it with a
`godebug tlssecpmlkem=1` line in `go.mod`, or `//go:debug tlssecpmlkem=1`
in the main package, as this repository's Go 1.26 test file does. See the
[Go TLS documentation](https://pkg.go.dev/crypto/tls#Config).

Set explicitly, `GODEBUG` removes these groups whatever
`CurvePreferences` says: `tlsmlkem=0` disables all ML-KEM hybrids and
`tlssecpmlkem=0` the NIST-curve ones, whether set in the environment or
by a `godebug` line in the main module's `go.mod`. FIPS 140-3 mode can restrict the groups too.
A hybrid-only configuration then fails to connect, and one with a
classical fallback quietly negotiates the classical group. Check
`ConnectionState.CurveID` if the hybrid is a requirement. The tests skip
the hybrid cases when `GODEBUG` disables them.
Hybrid key exchange does not replace certificate signatures or the
separate IEC 62351-4 E2E algorithms. These tests establish transport
compatibility, not IEC certification of an extended algorithm policy.

## Optional OpenSSL engines

Source inspection shows that `iec62351/ossltls` explicitly configures only
`P-256:P-384`. It does not expose a hybrid-group option, even when linked
against an OpenSSL version supporting ML-KEM. Native mode is TLS 1.2;
the legacy OpenSSL 1.0.2 engine has no TLS 1.3. The hybrid matrix above
exercises Go's `crypto/tls` transport, not the optional OpenSSL engines.

## Reproduce

```sh
go test ./iec62351 -run 'TestTLSHybridCompatibility$' -v
```

The NIST-curve hybrids are added to the test by a file with a `go1.26`
build constraint, so the module continues to build and test on Go 1.25. Production TLS policy is unchanged.
