#!/bin/bash
# This script assumes you have a brew install of openssl1.1.1g and python3.7.7 that is using openssl1.1.1g.

PYTHON_TMP_DIR=_tmp_python_client

pip3 uninstall aerospike -y
git clone https://github.com/aerospike/aerospike-client-python.git $PYTHON_TMP_DIR
cd $PYTHON_TMP_DIR
# python client v3.10.0 uses C client v4.6.10
git clone https://github.com/aerospike/aerospike-client-c.git --branch 5.1.1 --single-branch
cd aerospike-client-c
git submodule update --init
make
cd ..
export DOWNLOAD_C_CLIENT=0
export AEROSPIKE_C_HOME=$(pwd)/aerospike-client-c
python3 setup.py build --force
python3 setup.py install
cd ..
