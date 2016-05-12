#!/bin/bash
#
# Aerospike Backup/Restore Test
#
# Copyright (c) 2008-2016 Aerospike, Inc. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

function clear_work {
	if [ -d work ]; then
		rm -r work
	fi
}

function make_work {
	clear_work
	mkdir work work/state work/state/smd work/udf
}

function handle_signal {
	echo "received signal"
}

function test_process {
	if [ -f work/state/asd.pid ]; then
		echo "asd process already exists with PID $(cat work/state/asd.pid)"
		exit 1
	fi
}

function wait_process {
	for i in $(seq 5); do
		if [ -f work/state/asd.pid ]; then
			echo "asd process running"
			exit 0
		fi

		sleep 1
	done

	echo "asd process did not start"
	exit 1
}

function start_process {
	test_process

	OS=$(uname -s)
	ARCH=$(uname -m)
	DIRS=/usr/bin

	if [ -n "${ASREPO}" ]; then
		DIRS="${ASREPO}/target/${OS}-${ARCH}/bin ${DIRS}"
	fi

	trap handle_signal SIGINT SIGTERM

	for DIR in ${DIRS}; do
		if [ -x ${DIR}/asd ]; then
			echo "starting ${DIR}/asd"
			make_work
			${DIR}/asd --config aerospike-cs.conf >"${1}" 2>&1
			echo "${DIR}/asd exited"
			clear_work
			exit 0
		fi
	done

	echo "no asd binary found, checked directories: ${DIRS}"
	exit 1
}

function stop_process {
	if [ ! -f work/state/asd.pid ]; then
		echo "no running asd process"
		exit 1
	fi

	kill $(cat work/state/asd.pid)
}

function usage {
	echo "usage: asd.sh start log-file"
	echo "       asd.sh test|wait|stop|clean"
}

if [ -z "${1}" ]; then
	usage
	exit 1
fi

case "${1}" in
	start)
		if [ -z "${2}" ]; then
			echo missing log file argument
			usage
			exit 1
		fi

		start_process "${2}"
		exit 0
		;;
	test)
		test_process
		exit 0
		;;
	wait)
		wait_process
		exit 0
		;;
	stop)
		stop_process
		exit 0
		;;
	clean)
		clear_work
		exit 0
		;;
esac

echo "invalid argument: ${1}"
usage
exit 1

