#!/bin/bash

if [ -z "${1}" ]; then
	echo please specify the directory for the Python environment
	exit 1
fi

if [ -z "${2}" ]; then
	echo please specify a path to a test file/directory
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
else
	. "${1}"/bin/activate
fi

set -e

py.test --dir-mode ${2}
py.test --file-mode ${2}

