#!/usr/bin/env bash
VERSION=$(git rev-parse HEAD | cut -c -8)
BUILD_DEPS_REDHAT="readline which autoconf libtool" #readline-devel flex
BUILD_DEPS_UBUNTU="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libcurl4-openssl-dev libzstd-dev libjansson-dev"
BUILD_DEPS_DEBIAN="libpsl-dev autotools-dev automake libtool cmake pkg-config zlib1g-dev build-essential libssl-dev libcurl4-openssl-dev libzstd-dev libjansson-dev"
FPM_DEPS_DEBIAN="ruby-rubygems make rpm git rsync binutils"
FPM_DEPS_UBUNTU_2004="ruby make rpm git rsync binutils"
FPM_DEPS_UBUNTU="ruby-rubygems make rpm git rsync binutils"

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
  make -C build
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build
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
  make -C build
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build
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
  make -C build
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build
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
  make -C build
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build
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
  make -C build
  cd build
  make install
  cd ../..

  git clone https://github.com/aws/aws-sdk-cpp.git
  cd aws-sdk-cpp
  git checkout $AWS_SDK_VERSION
  git submodule update --init --recursive
  mkdir build
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
  make -C build
  cd build
  make install
  cd ../..
}

function install_deps_redhat-ubi9() {
  #todo redhat ubi9 does not have flex or readline-devel available in the yum repos
  yum install -y https://rpmfind.net/linux/centos-stream/9-stream/AppStream/x86_64/os/Packages/readline-devel-8.1-4.el9."$(uname -m)".rpm
  yum install -y https://rpmfind.net/linux/centos-stream/9-stream/AppStream/x86_64/os/Packages/flex-2.6.4-9.el9."$(uname -m)".rpm

  dnf -y install $BUILD_DEPS_REDHAT ruby rpmdevtools make git python3 python3-pip rsync
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  dnf install -y gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                      sqlite sqlite-devel sqlite-libs
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}
