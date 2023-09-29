#!/bin/bash
#
# Aerospike Backup/Restore Test
#
# Copyright (c) 2008-2023 Aerospike, Inc. All rights reserved.
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

PRE="work"

function clear_work {
	if [ -d work ]; then
		rm -rf $PRE/secret-agent
	fi
}

function make_work {
	clear_work
	mkdir $PRE $PRE/secret-agent $PRE/secret-agent/state
}

function clone {
    git clone https://github.com/aerospike/aerospike-secret-agent.git $PRE/secret-agent/aerospike-secret-agent
    cd $PRE/secret-agent/aerospike-secret-agent
    cd -
}

function build {
    make -C $PRE/secret-agent/aerospike-secret-agent/
}

function test_process {
	if [ -f $PRE/secret-agent/state/sa.pid ]; then
		echo "secret agent process already exists with PID $(cat $PRE/secret-agent/state/sa.pid)"
		exit 1
	fi
}

function start_process {
    make_work
    test_process

    clone
    build

	DIR=$PRE/secret-agent/aerospike-secret-agent/target

    if [ -x ${DIR}/aerospike-secret-agent ]; then
        echo "starting ${DIR}/aerospike-secret-agent"
        PID=$(${DIR}/aerospike-secret-agent --config-file secret-agent-conf.yaml >"${1}" 2>&1 & echo $!)
        echo $PID > $PRE/secret-agent/state/sa.pid
        exit 0
    fi	

	echo "no aerospike-secret-agent binary found, checked directories: ${DIR}"
	exit 1
}

function stop_process {
	if [ ! -f $PRE/secret-agent/state/sa.pid ]; then
		echo "no running secret agent process"
		exit 1
	fi

	kill $(cat $PRE/secret-agent/state/sa.pid)
    echo "killed secret agent process with PID $(cat $PRE/secret-agent/state/sa.pid)"
    rm -f $PRE/secret-agent/state/sa.pid
}

function usage {
	echo "usage: secret-agent.sh start log-file"
	echo "       secret-agent.sh test|stop|clean"
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
	stop)
		stop_process
		exit 0
		;;
    test)
        test_process
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

