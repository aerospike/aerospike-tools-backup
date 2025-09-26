alias make='make -j8'
function build_packages(){
  if [ "$ENV_DISTRO" = "" ]; then
    echo "ENV_DISTRO is not set"
    return
  fi
  cd "$GIT_DIR"
  git submodule update --init --recursive
  export ARCH=$(uname -m)

  if [ "$ENV_DISTRO" = "amazon-2023" ] || [ "$ENV_DISTRO" = "redhat-el8" ] || [ "$ENV_DISTRO" = "redhat-el9" ]; then
    make EVENT_LIB=libuv AWS_SDK_STATIC_PATH=/usr/local/lib JANSSON_STATIC_PATH=/usr/local/lib/
  else
    make EVENT_LIB=libuv ZSTD_STATIC_PATH=/usr/lib/$ARCH-linux-gnu AWS_SDK_STATIC_PATH=/usr/local/lib CURL_STATIC_PATH=/usr/local/lib OPENSSL_STATIC_PATH=/usr/lib/$ARCH-linux-gnu AWS_SDK_STATIC_PATH=/usr/local/lib JANSSON_STATIC_PATH=/usr/lib/$ARCH-linux-gnu
  fi

  cd $PKG_DIR
  echo "building package for $BUILD_DISTRO"

  if [[ $ENV_DISTRO == *"ubuntu"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"debian"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"redhat"* ]]; then
    make rpm
  elif [[ $ENV_DISTRO == *"amazon"* ]]; then
    make rpm
  else
    make tar
  fi

  mkdir -p /tmp/output/$ENV_DISTRO
  cp -a $PKG_DIR/target/* /tmp/output/$ENV_DISTRO
}