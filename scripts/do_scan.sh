#!/bin/sh
#---------------------------------------------------------------#
# Scans a list of targets, send results into elasicsearch.
#
# [/csh:]> date "+%D"
# 05/11/22
#---------------------------------------------------------------#
#
_rootdir=''
_targetsf=''
_config=''
_nmap2es=''
_datadir=''
_httpxnse=''
_ntpldir=''
_bin_nmap=''
_bin_httpx=''
_bin_nuclei=''
_verbose=0

# print help
show_help() {
cat << _EOF_
Usage: $0 [-d] [-t] -h -v

Options:
-d, --datadir [directory]  :- Path to main directory (eg: santacruz)
-t, --targets [file]       :- Path to file containing a list of target hosts to scan (one per line)

-h, --help      :- Show this help message and exit
-v, --verbose   :- Verbose output

_EOF_
exit 0
}

# check config, set global vars
check_setup() {
	_config="${1}/conf/santacruz.yml"
        _nmap2es="${1}/scripts/nmap2es.py"
	_httpxnse="${1}/nmap_nse/httpx.nse"
	_ntpldir="${1}/nuclei-templates"
	_datadir="${1}/data"

	# check directories
	chk_dirs=(${_datadir} ${_ntpldir})
	for _dir in "${chk_dirs[@]}"; do
		if [ ! -d ${_dir} ]; then
			echo "error: No such directory, (${_dir})"
			exit -255
		fi
	done

	# check files
	chk_files=(${_config} ${_nmap2es} ${_httpxnse})
	for _file in "${req_files[@]}"; do
		if [ ! -f ${_file} ]; then
			echo "error: No such file, (${_file})"
			exit -255
		fi
	done

	# tool vars
	_tcount=`grep '^nmap-bin:\|^httpx-bin:\|^nuclei-bin:' ${_config} | awk 'END{print NR}'`
	if [ "${_tcount}" -eq 3 ]; then
		_bin_nmap=`grep '^nmap-bin:' ${_config} | awk '{print $2}'`
		_bin_httpx=`grep '^httpx-bin:' ${_config} | awk '{print $2}'`
		_bin_nuclei=`grep '^nuclei-bin:' ${_config} | awk '{print $2}'`

		tools=(${_bin_nmap} ${_bin_httpx} ${_bin_nuclei})
		for tool in "${tools[@]}"; do
			if [ ! -f ${tool} ]; then
				echo "error: No such file, (${_file}), check your configuration (${_config})"
				exit -255
			fi
		done
	else
		echo "error: Missing required tools, check your configuration (${_config})"
		exit -255
	fi

}

# parse arguments
parse_args() {
	_nargs=0
        args=${1}
	for arg in "$@"; do
		case ${arg} in
			-d|--datadir) shift
				_rootdir=${1}
				((_nargs++))
			;;

			-t|--targets) shift
				_targetsf=${1}
				((_nargs++))
			;;

			-v|--verbose) shift
				_verbose=1
				((_nargs++))
			;;

			-h|--help)
				show_help
			;;

			-*|--*)
				echo "error: unknown option ($arg)"
				show_help
			;;

			*) shift
			;;
		esac
	done

	[ "${_verbose}" -eq 0 ] && _nargs=3
	[ "${_nargs}" -ne 3 ] && show_help

	if [ ! -d ${_rootdir} ]; then
		echo "error: No such directory, (${_rootdir})"
		exit -255
	fi

	if [ ! -f ${_targetsf} ]; then
		echo "error: No such file, (${_targetsf})"
		exit -255
	fi
}

# preform discovery scan
stage_one_discovery_scan() {
}

# preform port scan
stage_two_port_scan() {
}

stage_three_nuclei_scan() {
}

# Run scan
run_scan() {
	# Stage 1
	stage_one_discovery_scan

	# Stage 2
        stage_two_port_scan

	# Stage 3
        stage_three_nuclei_scan
}

#---------------------------------------------------------------#
# main
#---------------------------------------------------------------#
parse_args "$@"
check_setup "${_rootdir}"
#
run_scan


exit 1

