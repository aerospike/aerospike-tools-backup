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

# without this Python block-buffers stdout when CI pipes it, so a long test
# file looks hung until it finishes
export PYTHONUNBUFFERED=1

PYTEST_FLAGS="-v --durations=25"

echo "=== ${2}: dir-mode ==="
py.test ${PYTEST_FLAGS} --dir-mode ${2}
echo "=== ${2}: file-mode ==="
py.test ${PYTEST_FLAGS} --file-mode ${2}

