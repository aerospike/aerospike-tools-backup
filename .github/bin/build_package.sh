#!/usr/bin/env bash
set -xeuo pipefail

alias make='make -j8'

function assert_dynamic_deps() {
  local allowed="libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1
    libgcc_s.so.1 libstdc++.so.6 libz.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1"
  case "$ENV_DISTRO" in
    el8)
      allowed+=" libcurl.so.4 libssl.so.1.1 libcrypto.so.1.1 libzstd.so.1"
      ;;
    el9|el10|amzn2023)
      allowed+=" libcurl.so.4 libssl.so.3 libcrypto.so.3 libzstd.so.1"
      ;;
    ubuntu26.04)
      allowed+=" libjitterentropy.so.3"
      ;;
  esac

  local bin lib needed fail=0
  for bin in asbackup asrestore; do
    needed=$(readelf -d "bin/$bin" | awk '/\(NEEDED\)/ { gsub(/[][]/, "", $NF); print $NF }')
    echo "$bin DT_NEEDED:" $needed
    for lib in $needed; do
      if ! printf '%s\n' $allowed | grep -qxF "$lib"; then
        echo "$bin has unexpected dynamic dependency $lib; link it statically or add it to the allowlist and the package depends" >&2
        fail=1
      fi
    done
  done
  return $fail
}

function build_packages(){

  if [ "${ENV_DISTRO:-}" = "" ]; then
    echo "ENV_DISTRO is not set" >&2
    return 1
  fi
  GIT_DIR=$(git rev-parse --show-toplevel)
  PKG_DIR=$GIT_DIR/pkg
  cd "$GIT_DIR"
  git config --global --add safe.directory '*'
  git submodule update --init --recursive
  export ARCH=$(uname -m)
  if [ -n "${PKG_VERSION:-}" ]; then
    export VERSION="$PKG_VERSION"
  fi
  if [ "$ENV_DISTRO" = "debian13" ]; then
    export CMAKE_ROOT=/opt/cmake-3.27.0-linux-x86_64/
  fi
  if [ "$ENV_DISTRO" = "amzn2023" ] || [ "$ENV_DISTRO" = "el8" ] || [ "$ENV_DISTRO" = "el9" ] || [ "$ENV_DISTRO" = "el10" ]; then
    # Static libuv from compile_deps; avoid -L/usr/local before dynamic -lcurl (system libcurl) so
    # -lssl/-lcrypto resolve to distro OpenSSL (see Makefile link order / PR review).
    make EVENT_LIB=libuv AWS_SDK_STATIC_PATH=/usr/local/lib JANSSON_STATIC_PATH=/usr/local/lib/ LIBUV_STATIC_PATH=/usr/local/lib
  else
    if [ "$ENV_DISTRO" = "ubuntu26.04" ]; then
      export ASBACKUP_LINK_JITTERENTROPY=1
    else
      unset ASBACKUP_LINK_JITTERENTROPY 2>/dev/null || true
    fi
    make EVENT_LIB=libuv ZSTD_STATIC_PATH=/usr/lib/$ARCH-linux-gnu AWS_SDK_STATIC_PATH=/usr/local/lib CURL_STATIC_PATH=/usr/local/lib OPENSSL_STATIC_PATH=/usr/lib/$ARCH-linux-gnu AWS_SDK_STATIC_PATH=/usr/local/lib JANSSON_STATIC_PATH=/usr/lib/$ARCH-linux-gnu LIBUV_STATIC_PATH=/usr/local/lib
  fi

  assert_dynamic_deps

  cd $PKG_DIR
  echo "building package for $BUILD_DISTRO"

  if [[ $ENV_DISTRO == *"ubuntu"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"debian"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"el"* ]]; then
    make rpm
  elif [[ $ENV_DISTRO == *"amzn"* ]]; then
    make rpm
  else
    make tar
  fi

  mkdir -p /tmp/output/$ENV_DISTRO
  cp -a $PKG_DIR/target/* /tmp/output/$ENV_DISTRO
}
