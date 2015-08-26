#!/bin/bash

which pylint >/dev/null

if [ ${?} -ne 0 ]; then
	echo pylint does not seem to be installed
	exit 1
fi

pylint --rcfile=pylintrc *.py
