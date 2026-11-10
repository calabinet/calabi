#!/usr/bin/env bash
# Build a relocatable, pinned FreeRDP SDK for one macOS slice. No Homebrew
# libraries are used. The caller combines and signs the runtime dylibs.
set -euo pipefail
arch="${1:?Pass arm64 or x86_64}"
work="${2:?Pass an absolute scratch path}"
case "$arch" in
  arm64) openssl_target=darwin64-arm64-cc ;;
  x86_64) openssl_target=darwin64-x86_64-cc ;;
  *) echo "Unsupported macOS architecture: $arch" >&2; exit 2 ;;
esac
sdk="$work/sdk"
mkdir -p "$sdk"
jobs="$(sysctl -n hw.ncpu)"
export MACOSX_DEPLOYMENT_TARGET=11.0
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
# Do not accidentally pick up an optional codec or crypto library from the host.
unset PKG_CONFIG_PATH CMAKE_PREFIX_PATH CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
export PKG_CONFIG_LIBDIR="$sdk/lib/pkgconfig"

fetch() {
  local name="$1" url="$2" digest="$3"
  local archive="$(dirname "$work")/$name"
  if [[ ! -f "$archive" ]]; then
    curl --fail --silent --show-error --location --retry 3 "$url" -o "$archive"
  fi
  printf '%s  %s\n' "$digest" "$archive" | shasum -a 256 -c -
  tar -xf "$archive" -C "$work"
}

fetch openssl-3.6.5.tar.gz https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz \
  a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98
fetch freerdp-3.33.0.tar.xz https://pub.freerdp.com/releases/freerdp-3.33.0.tar.xz \
  9cea38e972e3775e1ce83b30e9ae0cbf8d00af1c708c640e6244fc81bdb1e08b

(
  cd "$work/openssl-3.6.5"
  # no-module builds the legacy provider into libcrypto. No module lookup in
  # the build machine's OpenSSL prefix is needed for Windows authentication.
  perl Configure "$openssl_target" --prefix="$sdk" --libdir=lib --openssldir=/etc/ssl \
    shared no-module no-tests -Wl,-headerpad_max_install_names
  make -j "$jobs"
  make install_sw
)
crypto="$sdk/lib/libcrypto.3.dylib"
ssl="$sdk/lib/libssl.3.dylib"
crypto_id="$(otool -D "$crypto" | tail -n 1)"
install_name_tool -id '@rpath/libcrypto.3.dylib' "$crypto"
install_name_tool -id '@rpath/libssl.3.dylib' "$ssl"
if [[ "$crypto_id" != '@rpath/libcrypto.3.dylib' ]]; then
  install_name_tool -change "$crypto_id" '@rpath/libcrypto.3.dylib' "$ssl"
fi
codesign --force --sign - "$crypto"
codesign --force --sign - "$ssl"
if [[ "$arch" == "$(uname -m)" ]]; then
  DYLD_LIBRARY_PATH="$sdk/lib" "$sdk/bin/openssl" list -providers -provider legacy
fi

src="$work/freerdp-3.33.0"
channel_args=()
for channel in "$src"/channels/*/ChannelOptions.cmake; do
  name="$(basename "$(dirname "$channel")" | tr '[:lower:]' '[:upper:]')"
  case "$name" in
    CLIPRDR|DRDYNVC|DISP|RDPGFX)
      channel_args+=("-DCHANNEL_$name=ON" "-DCHANNEL_${name}_CLIENT=ON" "-DCHANNEL_${name}_SERVER=OFF") ;;
    *) channel_args+=("-DCHANNEL_$name=OFF") ;;
  esac
done
cmake -S "$src" -B "$work/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="$arch" -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
  -DCMAKE_INSTALL_PREFIX="$sdk" -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_NAME_DIR=@rpath \
  -DCMAKE_SKIP_INSTALL_RPATH=ON -DCMAKE_PREFIX_PATH="$sdk" -DOPENSSL_ROOT_DIR="$sdk" \
  -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DWITHOUT_FREERDP_3x_DEPRECATED=ON \
  -DWITH_CLIENT=OFF -DWITH_CLIENT_COMMON=ON -DWITH_SERVER=OFF -DWITH_SERVER_INTERFACE=OFF \
  -DWITH_CHANNELS=ON -DWITH_CLIENT_CHANNELS=ON -DWITH_SERVER_CHANNELS=OFF \
  -DWITH_APPLE_VIDEOTOOLBOX=ON -DWITH_OPENH264=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_CAIRO=OFF -DWITH_OPUS=OFF \
  -DWITH_JSON_DISABLED=ON -DWITH_WEBVIEW=OFF -DWITH_URIPARSER=OFF -DWITH_MANPAGES=OFF \
  -DWITH_SAMPLE=OFF -DWITH_WINPR_TOOLS=OFF -DWITH_CCACHE=OFF -DWITH_FUSE=OFF \
  "${channel_args[@]}"
cmake --build "$work/build" --parallel "$jobs"
cmake --install "$work/build"

mkdir -p "$sdk/licenses"
cp "$src/LICENSE" "$sdk/licenses/FreeRDP.txt"
cp "$work/openssl-3.6.5/LICENSE.txt" "$sdk/licenses/OpenSSL.txt"
