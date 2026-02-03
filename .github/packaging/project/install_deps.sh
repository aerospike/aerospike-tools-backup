#!/usr/bin/env bash
set -xeuo pipefail

PROCESSOR_COUNT=$(cat /proc/cpuinfo | grep processor | wc -l)
export CMAKE_BUILD_PARALLEL_LEVEL=$PROCESSOR_COUNT
function make_parallel() {
 make -j$PROCESSOR_COUNT $@
}

function clone_parallel() {
  # Run in parallel
  echo $1 | tr ' ' '\n' | \
    parallel -j$PROCESSOR_COUNT --bar 'git clone {}'
}


BUILD_DEPS_AMAZON="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git libidn2 libunistring libunistring-devel"
BUILD_DEPS_REDHAT_8="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_REDHAT_9="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_REDHAT_10="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_UBUNTU="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libzstd-dev libjansson-dev git"
BUILD_DEPS_DEBIAN="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libzstd-dev libjansson-dev git"
BUILD_DEPS_DEBIAN_13="libpsl-dev autotools-dev automake libtool pkg-config zlib1g-dev build-essential libssl-dev libzstd-dev libjansson-dev wget git"

FPM_DEPS_DEBIAN="ruby-rubygems make rpm rsync binutils"
FPM_DEPS_UBUNTU_2004="ruby make rpm rsync binutils"
FPM_DEPS_UBUNTU="ruby-rubygems make rpm rsync binutils"
FPM_DEPS_AMAZON="ruby rpmdevtools make python3 python3-pip rsync"
FPM_DEPS_REDHAT_8="python3 python3-pip rsync"
FPM_DEPS_REDHAT_9="ruby rpmdevtools make python3 python3-pip rsync zlib zlib-devel"
FPM_DEPS_REDHAT_10="ruby rpmdevtools make python3 python3-pip rsync zlib zlib-devel"

AWS_SDK_VERSION="1.10.55"
function install_deps_debian11() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt-get -y install $BUILD_DEPS_DEBIAN $FPM_DEPS_DEBIAN
  gem install fpm -v 1.17.0
}

function compile_deps_debian11() {
  pushd /opt

  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd
  popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd
  popd
}

function install_deps_debian12() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt -y install $BUILD_DEPS_DEBIAN $FPM_DEPS_DEBIAN
  gem install fpm -v 1.17.0
}

function compile_deps_debian12() {
  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd; popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_debian13() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt-get -y install $BUILD_DEPS_DEBIAN_13 $FPM_DEPS_DEBIAN
  pushd /tmp
  wget https://github.com/Kitware/CMake/releases/download/v3.27.0/cmake-3.27.0-linux-$(uname -m).tar.gz
  tar -zxvf cmake-3.27.0-linux-$(uname -m).tar.gz -C /opt
  cp -a /opt/cmake-3.27.0-linux-$(uname -m)/share/cmake-3.27 /usr/local/share/
  popd
  install /opt/cmake-3.27.0-linux-$(uname -m)/bin/ccmake /usr/local/bin/ccmake
  install /opt/cmake-3.27.0-linux-$(uname -m)/bin/cmake /usr/local/bin/cmake
  install /opt/cmake-3.27.0-linux-$(uname -m)/bin/cmake-gui /usr/local/bin/cmake-gui
  install /opt/cmake-3.27.0-linux-$(uname -m)/bin/cpack /usr/local/bin/cpack
  install /opt/cmake-3.27.0-linux-$(uname -m)/bin/ctest /usr/local/bin/ctest
  gem install fpm -v 1.17.0
}

function compile_deps_debian13() {
  export CMAKE_ROOT=/opt/cmake-3.27.0-linux-x86_64/
  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-8_14_1
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd; popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON -DCMAKE_PREFIX_PATH=/usr/local
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_ubuntu20.04() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt-get -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU_2004
  gem install fpm -v 1.17.0
}

function compile_deps_ubuntu20.04() {
  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd; popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_ubuntu22.04() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt-get -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU
  gem install fpm -v 1.17.0
}

function compile_deps_ubuntu22.04() {
  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build

  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd; popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_ubuntu24.04() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -o Acquire::Retries=5
  apt-get -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU
  gem install fpm -v 1.17.0
}

function compile_deps_ubuntu24.04() {
  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  git clone https://github.com/curl/curl.git
  pushd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make_parallel -C build
  pushd build
  make install
  popd; popd

  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_el8() {
  dnf -y update
  # install fpm
  dnf module enable -y ruby:2.7
  dnf -y install ruby ruby-devel redhat-rpm-config rubygems rpm-build make git
  gem install fpm -v 1.17.0
  dnf -y install $BUILD_DEPS_REDHAT_8 $FPM_DEPS_REDHAT_8
}

function compile_deps_el8() {
  pushd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  pushd gettext-0.21
  autoconf
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  pushd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  pushd readline
  git checkout readline-8.3
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/akheron/jansson.git
  pushd jansson
  autoreconf -i
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  pushd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  pushd flex-2.6.4
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/aws/s2n-tls.git
  pushd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  pushd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
}

function install_deps_el9() {
  dnf -y update
  dnf -y install $BUILD_DEPS_REDHAT_9 $FPM_DEPS_REDHAT_9
  gem install fpm -v 1.17.0
}

function compile_deps_el9() {
  pushd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  pushd gettext-0.21
  autoconf
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  pushd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  pushd readline
  git checkout readline-8.3
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/akheron/jansson.git
  pushd jansson
  autoreconf -i
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  pushd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  pushd flex-2.6.4
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/aws/s2n-tls.git
  pushd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  pushd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_el10() {
  dnf -y update
  dnf -y install $BUILD_DEPS_REDHAT_10 $FPM_DEPS_REDHAT_10
  gem install fpm -v 1.17.0
}

function compile_deps_el10() {
  # install libunistring
  pushd /opt
  curl -LO https://ftp.gnu.org/gnu/libunistring/libunistring-1.2.tar.xz
  tar xf libunistring-1.2.tar.xz
  pushd libunistring-1.2
  ./configure --prefix=/usr --libdir=/usr/lib64 --with-pkgconfigdir=/usr/lib64/pkgconfig
  make -j"$(nproc)"
  make install
  ldconfig
  pushd /opt
  rm -rf libunistring-1.2 libunistring-1.2.tar.xz

  # sanity
cat >/usr/lib64/pkgconfig/libunistring.pc <<'EOF'
prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib64
includedir=${prefix}/include

Name: libunistring
Description: Unicode string library
Version: 1.2
Libs: -L${libdir} -lunistring
Cflags: -I${includedir}
EOF
  export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
  pkg-config --modversion libunistring
  pkg-config --cflags --libs libunistring

  pushd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  pushd gettext-0.21
  autoconf
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  pushd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  pushd readline
  git checkout readline-8.3
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/akheron/jansson.git
  pushd jansson
  autoreconf -i
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  pushd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  pushd flex-2.6.4
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/aws/s2n-tls.git
  pushd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install
  make_parallel -C build
  pushd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}

function install_deps_amzn2023() {
  dnf -y update
  yum groupinstall -y 'Development Tools'
  dnf install -y $BUILD_DEPS_AMAZON $FPM_DEPS_AMAZON
  gem install fpm -v 1.17.0

  pushd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  pushd gettext-0.21
  autoconf
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  pushd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  pushd readline
  git checkout readline-8.3
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/akheron/jansson.git
  pushd jansson
  autoreconf -i
  ./configure
  make_parallel
  make install

  pushd /opt
  git clone https://github.com/libuv/libuv
  pushd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make_parallel
  make install
  popd

  pushd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  pushd flex-2.6.4
  ./configure

  make_parallel
  make install
  pushd /opt
  git clone https://github.com/aws/s2n-tls.git
  pushd s2n-tls
  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install
  pushd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  pushd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make_parallel -C build
  pushd build
  make install
  popd; popd
}
