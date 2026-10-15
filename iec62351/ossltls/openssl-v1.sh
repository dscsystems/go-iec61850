#!/usr/bin/env bash
# Builds OpenSSL 1.0.2u as static libraries into PREFIX, for the engine
# "openssl-v1" (build tags openssl,openssl_v1), and writes pkg-config files
# naming those archives into PREFIX/pkgconfig. It runs on Linux, and on
# Windows in an MSYS2 MINGW64 shell (with make, perl and the MinGW-w64 gcc).
# On Linux, OPENSSL_V1_CROSS=x86_64-w64-mingw32- cross-compiles it for
# Windows with that MinGW-w64 toolchain. Point the build at the files whose
# directory it prints:
#
#   iec62351/ossltls/openssl-v1.sh "$HOME/.cache/openssl-1.0.2u"
#   PKG_CONFIG_LIBDIR=$HOME/.cache/openssl-1.0.2u/pkgconfig \
#     go build -tags openssl,openssl_v1 ./cmd/ied-client
#
# An existing build in PREFIX is reused. The libraries name OpenSSL's own
# directories (OPENSSLDIR, ENGINESDIR) as /usr/local/ssl and
# /usr/local/lib/engines, on Windows under C:/Program Files, not PREFIX: a
# build directory, or on Windows a drive-relative path, would point the
# executables at files that others might write. OpenSSL 1.0.2 has been out of
# support since 2019: use it only for peers that need the static-DH suites.
set -euo pipefail

version=1.0.2u
sha256=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16
url=https://www.openssl.org/source/old/1.0.2/openssl-$version.tar.gz
# Changes when the build changes, so that an existing one is rebuilt.
build_id="$version 2"

[ $# -eq 1 ] || { echo "usage: $0 PREFIX" >&2; exit 2; }
msys=0 windows=0 cross=${OPENSSL_V1_CROSS:-} prefix=$1
case "$(uname -s)" in
MINGW* | MSYS*) msys=1 windows=1 prefix=$(cygpath -u "$prefix") ;; # PREFIX may be a Windows path
esac
[ -n "$cross" ] && windows=1
if [ "$windows" = 1 ]; then
	openssldir="C:/Program Files/Common Files/SSL" enginesdir="C:/Program Files/OpenSSL/lib/engines"
else
	openssldir=/usr/local/ssl enginesdir=/usr/local/lib/engines
fi
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd)

if [ ! -f "$prefix/lib/libssl.a" ] || [ ! -f "$prefix/lib/libcrypto.a" ] ||
	[ "$(cat "$prefix/build-id" 2>/dev/null)" != "$build_id" ]; then
	work=$(mktemp -d)
	trap "rm -rf '$work'" EXIT
	echo "building OpenSSL $version into $prefix" >&2
	cd "$work"
	curl -fsSL -o openssl.tar.gz "$url"
	echo "$sha256  openssl.tar.gz" | sha256sum --check --quiet
	if [ "$msys" = 1 ]; then
		# The tarball has symbolic links, which MSYS2 extracts as copies of
		# their targets: a second pass makes those whose target came later.
		tar -xzf openssl.tar.gz 2>/dev/null || tar -xzf openssl.tar.gz
	else
		tar -xzf openssl.tar.gz
	fi
	(
		cd "openssl-$version"
		# OpenSSL picks its own compiler (and adds the cross prefix to it): a
		# CC meant for Go would be doubled or, on Windows, a Windows path.
		unset CC CFLAGS
		# -std=gnu89: the 1.0.2 sources predate C23, the default of newer GCC.
		common=(no-shared no-ssl2 no-ssl3 no-comp no-weak-ssl-ciphers -std=gnu89
			--prefix="$prefix" --openssldir="$prefix/ssl")
		if [ -n "$cross" ]; then
			./Configure mingw64 no-asm --cross-compile-prefix="$cross" "${common[@]}" >"$work/config.log" 2>&1
		elif [ "$windows" = 1 ]; then
			./Configure mingw64 no-asm "${common[@]}" >"$work/config.log" 2>&1
		else
			./config -fPIC "${common[@]}" >"$work/config.log" 2>&1
		fi || { tail -30 "$work/config.log" >&2; exit 1; }
		# Configure names PREFIX in both; install still goes there.
		sed -i -e "s|^#define OPENSSLDIR .*|#define OPENSSLDIR \"$openssldir\"|" \
			-e "s|^#define ENGINESDIR .*|#define ENGINESDIR \"$enginesdir\"|" crypto/opensslconf.h
		[ "$(grep -c -e "^#define OPENSSLDIR \"$openssldir\"" -e "^#define ENGINESDIR \"$enginesdir\"" crypto/opensslconf.h)" = 2 ] || {
			echo "crypto/opensslconf.h: OPENSSLDIR/ENGINESDIR not set" >&2
			exit 1
		}
		# make depend regenerates header dependencies. It fails when
		# cross-compiling (it runs the host's makedepend), which the build does
		# not need: the release tarball carries them.
		make depend >"$work/depend.log" 2>&1 || [ -n "$cross" ] || { tail -30 "$work/depend.log" >&2; exit 1; }
		# Serial: the 1.0.2 makefiles are not safe for make -j.
		make >"$work/make.log" 2>&1 || { tail -30 "$work/make.log" >&2; exit 1; }
		rm -rf "$prefix/include" "$prefix/lib"
		make install_sw >"$work/install.log" 2>&1
	)
	echo "$build_id" >"$prefix/build-id"
fi

# OpenSSL's own .pc files leave the system libraries to Libs.private, which
# cgo does not read. Go runs as a Windows program there: Windows paths.
dir=$prefix syslibs="-ldl -pthread"
[ "$windows" = 1 ] && syslibs="-lws2_32 -lgdi32 -lcrypt32"
[ "$msys" = 1 ] && dir=$(cygpath -m "$prefix")
mkdir -p "$prefix/pkgconfig"
printf 'Name: libcrypto\nDescription: OpenSSL libcrypto %s (static)\nVersion: %s\nCflags: -I%s/include\nLibs: %s/lib/libcrypto.a %s\n' \
	"$version" "$version" "$dir" "$dir" "$syslibs" >"$prefix/pkgconfig/libcrypto.pc"
printf 'Name: libssl\nDescription: OpenSSL libssl %s (static)\nVersion: %s\nRequires: libcrypto\nCflags: -I%s/include\nLibs: %s/lib/libssl.a\n' \
	"$version" "$version" "$dir" "$dir" >"$prefix/pkgconfig/libssl.pc"
echo "$dir/pkgconfig"
