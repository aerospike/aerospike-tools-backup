#!/usr/bin/env bash
alias make='make -j8'

BUILD_DEPS_AMAZON="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git libidn2 libunistring libunistring-devel"
BUILD_DEPS_REDHAT_8="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_REDHAT_9="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_REDHAT_10="gcc-c++ libtool wget cmake openssl-devel libcurl-devel libzstd-devel which autoconf git" #readline-devel flex
BUILD_DEPS_UBUNTU="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libzstd-dev libjansson-dev"
BUILD_DEPS_DEBIAN="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libzstd-dev libjansson-dev"
FPM_DEPS_DEBIAN="ruby-rubygems make rpm git rsync binutils"
FPM_DEPS_UBUNTU_2004="ruby make rpm git rsync binutils"
FPM_DEPS_UBUNTU="ruby-rubygems make rpm git rsync binutils"
FPM_DEPS_AMAZON="ruby rpmdevtools make git python3 python3-pip rsync"
FPM_DEPS_REDHAT_8="python3 python3-pip rsync"
FPM_DEPS_REDHAT_9="ruby rpmdevtools make git python3 python3-pip rsync zlib zlib-devel"
FPM_DEPS_REDHAT_10="ruby rpmdevtools make git python3 python3-pip rsync zlib zlib-devel"

AWS_SDK_VERSION="1.10.55"
function install_deps_debian11() {
  apt -y install $BUILD_DEPS_DEBIAN $FPM_DEPS_DEBIAN
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..



}

function install_deps_debian12() {
  apt -y install $BUILD_DEPS_DEBIAN $FPM_DEPS_DEBIAN
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..
}

function install_deps_debian13() {
  apt -y install $BUILD_DEPS_DEBIAN $FPM_DEPS_DEBIAN
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-8_14_1
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..
}

function install_deps_ubuntu20.04() {
  apt -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU_2004
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..
}

function install_deps_ubuntu22.04() {
  apt -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..
}

function install_deps_ubuntu24.04() {
  apt -y install $BUILD_DEPS_UBUNTU $FPM_DEPS_UBUNTU
  gem install fpm

  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.43.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  git clone https://github.com/curl/curl.git
  cd curl
  git checkout curl-7_81_0
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
  make -C build -j8
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..
}

function install_deps_redhat-el8() {
  # install fpm
  dnf module enable -y ruby:2.7
  dnf -y install ruby ruby-devel redhat-rpm-config rubygems rpm-build make git
  gem install --no-document fpm

  dnf -y install $BUILD_DEPS_REDHAT_8 $FPM_DEPS_REDHAT_8

  cd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  cd gettext-0.21
  autoconf
  ./configure
  make
  make install

  cd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  cd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make
  make install

  cd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  cd readline
  git checkout readline-8.3
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/akheron/jansson.git
  cd jansson
  autoreconf -i
  ./configure
  make
  make install


  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  cd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  cd flex-2.6.4
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/aws/s2n-tls.git
  cd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  cd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install

  gem install fpm
}

function install_deps_redhat-el9() {

  dnf -y install $BUILD_DEPS_REDHAT_9 $FPM_DEPS_REDHAT_9

  cd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  cd gettext-0.21
  autoconf
  ./configure
  make
  make install

  cd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  cd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make
  make install

  cd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  cd readline
  git checkout readline-8.3
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/akheron/jansson.git
  cd jansson
  autoreconf -i
  ./configure
  make
  make install


  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  cd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  cd flex-2.6.4
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/aws/s2n-tls.git
  cd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  cd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..

  gem install fpm
}

function install_deps_redhat-el10() {
  curl -fsSL https://cdn-ubi.redhat.com/ubi.repo -o /etc/yum.repos.d/ubi.repo
  dnf install -y dnf-plugins-core
  dnf config-manager --set-enabled ubi-10-crb || true
  dnf install -y libunistring-devel libidn2-devel pkgconf-pkg-config

  dnf -y install $BUILD_DEPS_REDHAT_10 $FPM_DEPS_REDHAT_10

  cd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  cd gettext-0.21
  autoconf
  ./configure
  make
  make install

  cd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  cd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make
  make install

  cd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  cd readline
  git checkout readline-8.3
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/akheron/jansson.git
  cd jansson
  autoreconf -i
  ./configure
  make
  make install


  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  cd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  cd flex-2.6.4
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/aws/s2n-tls.git
  cd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  cd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd ../..

  gem install fpm
}

function install_deps_amazon-2023() {
  yum groupinstall -y 'Development Tools'
  dnf install -y $BUILD_DEPS_AMAZON $FPM_DEPS_AMAZON


  cd /opt
  wget https://mirrors.ocf.berkeley.edu/gnu/gettext/gettext-0.21.tar.gz
  tar -zxvf gettext-0.21.tar.gz
  cd gettext-0.21
  autoconf
  ./configure
  make
  make install

  cd /opt
  git clone  https://github.com/rockdaboot/libpsl.git
  cd libpsl
  git checkout 0.21.5
  ./autogen.sh
  ./configure
  make
  make install

  cd /opt
  git clone https://https.git.savannah.gnu.org/git/readline.git
  cd readline
  git checkout readline-8.3
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/akheron/jansson.git
  cd jansson
  autoreconf -i
  ./configure
  make
  make install


  cd /opt
  git clone https://github.com/libuv/libuv
  cd libuv
  git checkout v1.42.0
  sh autogen.sh
  ./configure
  make
  make install
  cd ..

  cd /opt
  wget https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz
  tar -zxvf flex-2.6.4.tar.gz
  cd flex-2.6.4
  ./configure
  make
  make install

  cd /opt
  git clone https://github.com/aws/s2n-tls.git
  cd s2n-tls

  cmake . -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
  cmake --build build
  make install

  cd /opt
  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build -j8
  cd build
  make install
  cd

  gem install fpm
}
