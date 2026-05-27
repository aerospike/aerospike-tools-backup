#!/usr/bin/env bash
set -xeuo pipefail

alias make='make -j8'
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
