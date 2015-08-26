#!/bin/bash

if [ -z "${1}" ]; then
	echo please specify the directory for the Python environment
	exit 1
fi

if [ ! -d "${1}" ]; then
	echo creating Python environment in "${1}"
	virtualenv "${1}"
	. "${1}"/bin/activate
	pip install -r requirements.txt
else
	. "${1}"/bin/activate
fi

py.test --dir-mode test
py.test --file-mode test
