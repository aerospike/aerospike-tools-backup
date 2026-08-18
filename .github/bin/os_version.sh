#!/usr/bin/env bash
# shellcheck disable=SC1091
# ------------------------------------------------------------------------------
# Copyright 2012-2023 Aerospike, Inc.
#
# Portions may be licensed to Aerospike, Inc. under one or more contributor
# license agreements.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
# ------------------------------------------------------------------------------

OPT_LONG=0

if [ "$1" = "-long" ]
then
	OPT_LONG=1
fi

error() {
	echo 'error:' "$*" >&2
}

main() {

	local kernel=''
	local distro_id=''
	local distro_version=''
	local distro_long=''
	local distro_short=''

	kernel=$(uname -s | tr '[:upper:]' '[:lower:]')

	# macOS: emit "macos<major>" from the product version (26.0 -> macos26).
	# This is the single source of truth for the platform field of the .pkg file
	# name (see MAC_PKG in pkg/Makefile). CI must call this script rather than
	# re-deriving the token from a runner label, so the name a release publishes
	# is the name a local `make -C pkg osx-pkg` produces. The token records the
	# macOS generation the artifact was built on, not a minimum it supports:
	# nothing pins MACOSX_DEPLOYMENT_TARGET. It is what keeps one release's
	# per-runner artifacts distinct.
	if [ "$kernel" = 'darwin' ]
	then
		local mac_version=''
		mac_version=$(sw_vers -productVersion)
		# This script has no `set -e`, so an sw_vers that fails or prints
		# nothing would otherwise emit the bare token "macos" -- non-empty,
		# so pkg/Makefile's prep-mac guard would wave it through and the
		# release would ship aerospike-<tool>-<version>-macos-<arch>.pkg.
		if [ -z "$mac_version" ]
		then
			error "sw_vers -productVersion returned nothing."
			exit 1
		fi
		echo "macos${mac_version%%.*}"
		exit 0
	fi

	# Everything below is Linux-only.
	if [ "$kernel" != 'linux' ]
	then
		error "$kernel is not supported."
		exit 1
	fi

	if [ -f /etc/os-release ]
	then
		. /etc/os-release
		distro_id=${ID,,}
		distro_version=${VERSION_ID}
	elif [ -f /etc/issue ]
	then
		issue=$(cat /etc/issue | tr '[:upper:]' '[:lower:]')
		case "$issue" in
		*'redhat'* | *'rhel'* | *'red hat'* )
			distro_id='rhel'
			;;
		*'debian'* )
			distro_id='debian'
			;;
		* )
			error "/etc/issue contained an unsupported linux distribution: $issue"
			exit 1
			;;
		esac

		case "$distro_id" in
		'rhel' )
			local release=''
			release=$(cat /etc/redhat-release | tr '[:upper:]' '[:lower:]')
			release_version=${release##*release}
			distro_version=${release_version%%.*}
			;;
		'debian' )
			debian_version=$(cat /etc/debian_version | tr '[:upper:]' '[:lower:]')
			distro_version=${debian_version%%.*}
			;;
		* )
			error "/etc/issue contained an unsupported linux distribution: $issue"
			exit 1
			;;
		esac
	fi

	distro_id=${distro_id//[[:space:]]/}
	distro_version=${distro_version//[[:space:]]/}

	# Second chance for pre-release versions.
	if [ -z "$distro_version" ]
	then
		case "$distro_id" in
		'debian' )
		debian_version=$(cat /etc/debian_version | tr '[:upper:]' '[:lower:]')
		if [[ "$debian_version" = "bullseye"* ]]
		then
			debian_version=11
		elif [[ "$debian_version" = "bookworm"* ]]
		then
			debian_version=12
		elif [[ "$debian_version" = "trixie"* ]]
		then
			debian_version=13
		fi
		distro_version=${debian_version%%.*}
		;;
		esac
	fi

	case "$distro_id" in
	'rhel' | 'redhat' | 'red hat' )
		distro_long="${distro_id}${distro_version%%.*}"
		distro_short="el${distro_version%%.*}"
		;;
	'fedora' )
		distro_long="${distro_id}${distro_version}"
		distro_short="fc${distro_version}"
		;;
	* )
		distro_long="${distro_id}${distro_version}"
		distro_short="${distro_id}${distro_version}"
		;;
	esac

	if [ "$OPT_LONG" = "1" ]
	then
		echo "${distro_long}"
	else
		echo "${distro_short}"
	fi
	exit 0
}

main
