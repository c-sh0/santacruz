#!/bin/sh
#---------------------------------------------------------------#
# Scans a list of targets, send results into elasicsearch.
#
# [/csh:]> date "+%D"
# 05/11/22
#
#################
# Help Function #
#################
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

#################
# Date Function #
#################
mkdate() {
	_dtype=${1}

	if [ "${_dtype}" == 'dt' ]; then
		local _d=`date +"%Y-%m-%d %T.%3N (%Z)"`

	elif [ "${_dtype}" == 'd' ]; then
		local _d=`date +"%Y-%m-%d"`
	fi

	echo "${_d}"
}

######################
# Parseargs Function #
######################
_rootdir=''
_targetsf=''
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

	[ "${_nargs}" -ne 2 ] && show_help

	if [ ! -d ${_rootdir} ]; then
		echo "error: No such directory, (${_rootdir})"
		exit -255
	fi

	if [ ! -f ${_targetsf} ]; then
		echo "error: No such file, (${_targetsf})"
		exit -255
	fi
}
parse_args "$@"

###########
# Globals #
###########
_scandate="$(mkdate "d")"
_datadir="${_rootdir}/data"
_confdir="${_rootdir}/conf"
_scriptdir="${_rootdir}/scripts"
_nsedir="${_rootdir}/nmap_nse"
_nucleitpldir="${_datadir}/nuclei-templates"
_nucleidir="${_datadir}/nuclei"
_nmapdir="${_datadir}/nmap"
_nmap2es="${_scriptdir}/nmap2es.py"
_nmapparse="${_scriptdir}/nmapparse.py"
_httpxnse="${_nsedir}/httpx.nse"
#
_dscan_xml="${_nmapdir}/dsicovery_scan-${_scandate}.xml"
_pscan_xml="${_nmapdir}/portscan-${_scandate}.xml"
_pscan_targets="${_nmapdir}/portscan-${_scandate}.targets"
_nuclei_targets="${_nucleidir}/nuclei-${_scandate}.targets"
#
_nmap='/usr/local/bin/nmap'
_httpx='/usr/local/bin/httpx'
_nuclei='/usr/local/bin/nuclei'


#####################
# Pre-scan function #
#####################
pre_scan() {
	chk_dirs=(${_datadir} ${_confdir} ${_scriptdir} ${_nsedir} ${_nucleitpldir})
	for _dir in "${chk_dirs[@]}"; do
		if [ ! -d ${_dir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() Error: No such directory, (${_dir})"
			exit -255
		fi
	done

	# check files
	chk_files=(${_nmap2es} ${_nmapparse} ${_httpxnse})
	for _file in "${chk_files[@]}"; do
		if [ ! -f ${_file} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() Error: No such file, (${_file})"
			exit -255
		fi
	done

	# tools
	tools=(${_nmap} ${_httpx} ${_nuclei})
	for tool in "${tools[@]}"; do
		if [ ! -f ${tool} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() Error: No such file, (${_file})"
			exit -255
		fi
	done

	# create nmap output dir if not exist
	if [ ! -d ${_nmapdir} ]; then
		echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nmapdir}"
		mkdir -p -m 700 ${_nmapdir}
		if [ ! -d ${_nmapdir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() Error: No such directory, (${_nmapdir})"
			exit -255
		fi
	fi

	# create nuclei output dir if not exist
	if [ ! -d ${_nucleidir} ]; then
		echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nucleidir}"
		mkdir -p -m 700 ${_nucleidir}
		if [ ! -d ${_nucleidir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() Error: No such directory, (${_nucleidir})"
			exit -255
		fi
	fi

	# check for exsiting output files
	chk_files=(${_dscan_xml} ${_pscan_xml} ${_pscan_targets} ${_nuclei_targets})
	for _file in "${chk_files[@]}"; do
		if [ -f ${_file} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]} Found ${_file}, Scan already running?, exit()"
			exit -255
		fi
	done

}

#################
# Scan function #
#################
run_scan() {
	###############
	# Nmap notes:
	# * For some reason the --open flag needs one of the last optionsotherwise,
	#   nmap will still write filtered port information into the log files
	#   this will result in HUGE log files when scanning a lot of hosts
	# * Don't use -v0 (silent) flag, instead redirect stdio to /dev/null otherwise
	#   nmap will still write filtered port information to the output log files
	#   regardless if --open has been set. https://github.com/nmap/nmap/issues/236
	###############
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() START"

	#------------------------------------------------------------------------------------#
	# Nmap discovery scan
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Nmap Discovery scan, Starting..."
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Logfile (${_dscan_xml})"

		${_nmap} \
			-n -sn \
			-PS21-23,25,53,80,110-111,135,139,143,161,443,445,993,995,1723,3306,3389,5900,8080 \
			-PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 \
			--min-parallelism 100 --min-hostgroup 100 --min-rate 20000 --randomize-hosts --disable-arp-ping --max-retries 1 \
		-iL ${_targetsf} -oX ${_dscan_xml} > /dev/null

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Nmap discovery scan, Complete."

	# Create portscan targets file
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Create Portscan targets (${_pscan_targets})"
	${_nmapparse} --file ${_dscan_xml} --data-type ip > ${_pscan_targets}

	#------------------------------------------------------------------------------------#
	# Nmap port scan (full port scan)
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Nmap Portscan, Starting..."
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Logfile (${_pscan_xml})"

		${_nmap} \
			 -sS -p- \
			--script=${_nsedir}/ --script-timeout=3 \
			--min-parallelism 100 --min-rate 20000 --min-hostgroup 100 --randomize-hosts \
		--open -iL ${_pscan_targets} -oX ${_pscan_xml} > /dev/null

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Nmap portscan, Complete."

	# Create nuclei targets file (nmap httpx.nse results)
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [CMD]: Create Nuclei targets (${_nuclei_targets})"
	${_nmapparse} --file ${_pscan_xml} --data-type httpx > ${_nuclei_targets}

	#------------------------------------------------------------------------------------#
	# Nuclei scan
	#------------------------------------------------------------------------------------#

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() END"
}

#############
# lock file #
#############
_lockf="${_datadir}/.scan.lock"
if [ -e "${_lockf}" ]; then
	if [[ $(kill -0 `cat ${_lockf}`) -eq 0 ]]; then
		echo "[$(mkdate "dt")] Found ${_lockf}, exit()"
		exit -1
	fi
fi

trap "rm -f ${_lockf}; exit" INT TERM EXIT
echo $$ > ${_lockf}

##############
# Start Scan #
##############
pre_scan
run_scan

exit 0

