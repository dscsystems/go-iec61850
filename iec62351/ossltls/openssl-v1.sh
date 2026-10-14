#!/usr/bin/env bash
# Builds OpenSSL 1.0.2u as static libraries into PREFIX, for the engine
# "openssl-v1" (build tags openssl,openssl_v1), and writes pkg-config files
# naming those archives into PREFIX/pkgconfig. Point the build at them:
#
#   iec62351/ossltls/openssl-v1.sh "$HOME/.cache/openssl-1.0.2u"
#   PKG_CONFIG_LIBDIR=$HOME/.cache/openssl-1.0.2u/pkgconfig \
#     go build -tags openssl,openssl_v1 ./cmd/ied-client
#
# An existing build in PREFIX is reused. OpenSSL 1.0.2 has been out of
# support since 2019: use it only for peers that need the static-DH suites.
set -euo pipefail

version=1.0.2u
sha256=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16
url=https://www.openssl.org/source/old/1.0.2/openssl-$version.tar.gz

[ $# -eq 1 ] || { echo "usage: $0 PREFIX" >&2; exit 2; }
mkdir -p "$1"
prefix=$(cd "$1" && pwd)

if [ ! -f "$prefix/lib/libssl.a" ] || [ ! -f "$prefix/lib/libcrypto.a" ]; then
	work=$(mktemp -d)
	trap "rm -rf '$work'" EXIT
	echo "building OpenSSL $version into $prefix" >&2
	curl -fsSL -o "$work/openssl.tar.gz" "$url"
	echo "$sha256  $work/openssl.tar.gz" | sha256sum --check --quiet
	tar -C "$work" -xzf "$work/openssl.tar.gz"
	(
		cd "$work/openssl-$version"
		# -std=gnu89: the 1.0.2 sources predate C23, the default of newer GCC.
		./config no-shared no-ssl2 no-ssl3 no-comp no-weak-ssl-ciphers -fPIC -std=gnu89 \
			--prefix="$prefix" --openssldir="$prefix/ssl" >"$work/config.log" 2>&1
		make depend >"$work/depend.log" 2>&1
		# Serial: the 1.0.2 makefiles are not safe for make -j.
		make >"$work/make.log" 2>&1 || { tail -30 "$work/make.log" >&2; exit 1; }
		make install_sw >"$work/install.log" 2>&1
	)
fi

# OpenSSL's own .pc files leave -ldl to Libs.private, which cgo does not read.
mkdir -p "$prefix/pkgconfig"
printf 'Name: libcrypto\nDescription: OpenSSL libcrypto %s (static)\nVersion: %s\nCflags: -I%s/include\nLibs: %s/lib/libcrypto.a -ldl -pthread\n' \
	"$version" "$version" "$prefix" "$prefix" >"$prefix/pkgconfig/libcrypto.pc"
printf 'Name: libssl\nDescription: OpenSSL libssl %s (static)\nVersion: %s\nRequires: libcrypto\nCflags: -I%s/include\nLibs: %s/lib/libssl.a\n' \
	"$version" "$version" "$prefix" "$prefix" >"$prefix/pkgconfig/libssl.pc"
echo "$prefix/pkgconfig"
