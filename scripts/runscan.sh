#!/bin/sh
#---------------------------------------------------------------#
# Scans a list of targets, send results into elasicsearch.
#
# [/csh:]> date "+%D"
# 05/11/22
#---------------------------------------------------------------#
# defaults
_targetsf=''
_rootdir=''
_config=''
_nmap2es=''
_nmapparse=''
_datadir=''
_nmapdir=''
_nucleidir=''
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
-rd, --rootdir [directory]  :- Path to root directory
-t,  --targets [file]       :- Path to file containing a list of target hosts to scan (one per line)

-h, --help      :- Show this help message and exit
-v, --verbose   :- Verbose output

_EOF_
exit 0
}

# date/time
mkdate() {
	_dtype=${1}

	if [ "${_dtype}" == 'dt' ]; then
		local _d=`date +"%Z: %Y-%m-%d %T.%3N"`

	elif [ "${_dtype}" == 'd' ]; then
		local _d=`date +"%Y-%m-%d"`
	fi

	echo "${_d}"
}

# check config, set global vars
check_setup() {
	_config="${1}/conf/santacruz.yml"
	_nmap2es="${1}/scripts/nmap2es.py"
	_nmapparse="${1}/scripts/nmapparse.py"
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
	chk_files=(${_config} ${_nmap2es} ${_nmapparse} ${_httpxnse})
	for _file in "${chk_files[@]}"; do
		if [ ! -f ${_file} ]; then
			echo "error: No such file, (${_file})"
			exit -255
		fi
	done

	# create nmap output dir if not exist
	_nmapdir="${_datadir}/nmap"
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nmapdir}"
	mkdir -p ${_nmapdir}
	if [ ! -d ${_nmapdir} ]; then
		echo "error: No such directory, (${_nmapdir})"
		exit -255
	fi

	# create nuclei output dir if not exist
	_nucleidir="${_datadir}/nuclei"
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nucleidir}"
	mkdir -p ${_nucleidir}
	if [ ! -d ${_nucleidir} ]; then
		echo "error: No such directory, (${_nucleidir})"
		exit -255
	fi

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
			-rd|--rootdir) shift
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

	[ "${_verbose}" -eq 0 ] && ((_nargs++))
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

# run discovery scan
discovery_scan_01() {
	# logfile
	_logf="${1}"
	_pscan_targets="${2}"

	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} START"

	# nmap args
	# (-V0 (silent), -n (No DNS resolution), -sn (No port scan)
	_OPTS='-v0 -n -sn'
	# TCP SYN Ping ports
	_PS='-PS21-23,25,53,80,110-111,135,139,143,161,443,445,993,995,1723,3306,3389,5900,8080'
	# UDP Ping ports
	_PU='-PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152'
	# tuning options
	_TN='--min-parallelism 100 --min-hostgroup 100 --min-rate 20000 --randomize-hosts --disable-arp-ping --max-retries 1'

	# do scan
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: ${_bin_nmap} ${_OPTS} ${_PS} ${_PU} ${_TN} -iL ${_targetsf} -oX ${_logf}"
	${_bin_nmap} ${_OPTS} ${_PS} ${_PU} ${_TN} -iL ${_targetsf} -oX ${_logf}

	# create portscan targets file
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: ${_nmapparse} --file ${_logf} --data-type ip > ${_pscan_targets}"
	${_nmapparse} --file ${_logf} --data-type ip > ${_pscan_targets}

	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} END"
}


# run port scan
port_scan_02() {
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} START"
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} END"
}

# run nuclei scan
nuclei_scan_03() {
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} START"
	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} END"
}


# Run scan
run_scan() {
	# date (log file name)
	_logfd="$(mkdate "d")"
	_discovery_log="${_nmapdir}/dsicovery_scan-${_logfd}.xml"
	_portscan_log="${_nmapdir}/portscan-${_logfd}.xml"
	_portscan_targets="${_nmapdir}/portscan-${_logfd}.hosts"

	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} START"

	# check files
	chk_files=(${_discovery_log} ${_portscan_log} ${_portscan_targets})
	for _file in "${chk_files[@]}"; do
		if [ -f ${_file} ]; then
			echo "[$(mkdate "dt")]: ${FUNCNAME[0]} Found ${_file}, Scan already running?, exit()"
			exit -255
		fi
	done

	# Stage 1
	discovery_scan_01 "${_discovery_log}" "${_portscan_targets}"

	# Stage 2
	port_scan_02 "${_portscan_log}" "${_portscan_targets}"

	# Stage 3
	nuclei_scan_03 "${_logfd}"

	echo "[$(mkdate "dt")]: ${FUNCNAME[0]} END"
}

#---------------------------------------------------------------#
# main
#---------------------------------------------------------------#
parse_args "$@"
check_setup "${_rootdir}"

# lock file
_lockf="${_datadir}/.scan.lock"
if [ -e "${_lockf}" ]; then
	if [[ $(kill -0 `cat ${_lockf}`) -eq 0 ]]; then
		echo "[$(mkdate "dt")]: Found ${_lockf}, exit()"
		exit -1
	fi
fi

trap "rm -f ${_lockf}; exit" INT TERM EXIT
echo $$ > ${_lockf}

run_scan


exit 1

