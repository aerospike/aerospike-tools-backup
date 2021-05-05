#!/bin/bash

if [ -z "${1}" ]; then
	echo please specify the directory for the Python environment
	exit 1
fi

if ! command -v virtualenv &> /dev/null
then
	sudo python3 -m pip install pipenv
fi

if [ ! -d "${1}" ]; then
	echo creating Python environment in "${1}"
	virtualenv "${1}"
	. "${1}"/bin/activate
	pip install -r requirements.txt
	cd "${1}"

	#if [[ "$OSTYPE" == "darwin"* || ]]; then
		# MacOS, build the aerospike client from source since the pip3 build
		# doesn't link properly with newer versions of OpenSSL
	../install_aerospike_python.sh
	#fi
	cd ..
else
	. "${1}"/bin/activate
fi

#py.test --file-mode test/integration/test_value.py::test_boolean_value
py.test --dir-mode test/integration
py.test --file-mode test/integration
