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
-r, --rundir  [directory] :- Path to run directory (data, scripts, etc...)
-t, --targets [file]      :- Path to file containing a list of target hosts to scan (one per line)

-h, --help      :- Show this help message and exit

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
_rundir=''
_targetsf=''
parse_args() {
	_nargs=0
        args=${1}
	for arg in "$@"; do
		case ${arg} in
			-r|--rundir) shift
				_rundir=${1}
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

	if [ ! -d ${_rundir} ]; then
		echo "error: No such directory, (${_rundir})"
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
_datadir="${_rundir}/data"
_confdir="${_rundir}/conf"
_scriptdir="${_rundir}/scripts"
_nsedir="${_rundir}/nmap/nse"
_nucleitpldir="${_datadir}/nuclei-templates"
_nucleidir="${_datadir}/nuclei"
_nmapdir="${_datadir}/nmap"
_nmap2es="${_scriptdir}/nmap2es.py"
_nmapparse="${_scriptdir}/nmapparse.py"
_httpxnse="${_nsedir}/httpx.nse"
#
_conffile="${_confdir}/santacruz.yml"
_nucleiconf="${_confdir}/nuclei.yml"
_dscan_xml="${_nmapdir}/dsicovery_scan-${_scandate}.xml"
_pscan_xml="${_nmapdir}/port_scan-${_scandate}.xml"
_pscan_targets="${_nmapdir}/port_scan-${_scandate}.targets"
_nuclei_targets="${_nucleidir}/nuclei-${_scandate}.targets"
#
_nmap='/usr/local/bin/nmap'
_httpx='/usr/local/bin/httpx'
_nuclei='/usr/local/bin/nuclei'


#####################
# Pre-scan function #
#####################
pre_scan() {
	# check for nuclei templates dir, (git checkout if it does not exist)
	if [ ! -d ${_nucleitpldir} ]; then
		echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: git clone https://github.com/projectdiscovery/nuclei-templates.git"
		_gitcmd=`which git`
		if [ ! -e ${_gitcmd} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: 'git', command not found"
			exit -255
		fi
		${_gitcmd} clone https://github.com/projectdiscovery/nuclei-templates.git ${_nucleitpldir}
	fi

	chk_dirs=(${_datadir} ${_confdir} ${_scriptdir} ${_nsedir} ${_nucleitpldir})
	for _dir in "${chk_dirs[@]}"; do
		if [ ! -d ${_dir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: No such directory, (${_dir})"
			exit -255
		fi
	done

	# check files
	chk_files=(${_nmap2es} ${_nmapparse} ${_httpxnse} ${_conffile} ${_nucleiconf})
	for _file in "${chk_files[@]}"; do
		if [ ! -f ${_file} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: No such file, (${_file})"
			exit -255
		fi
	done

	# check for tool installation
	tools=(${_nmap} ${_httpx} ${_nuclei})
	for tool in "${tools[@]}"; do
		if [ ! -f ${tool} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: No such file, (${_file})"
			exit -255
		fi
	done

	# create nmap output dir if not exist
	if [ ! -d ${_nmapdir} ]; then
		echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nmapdir}"
		mkdir -p -m 700 ${_nmapdir}
		if [ ! -d ${_nmapdir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: No such directory, (${_nmapdir})"
			exit -255
		fi
	fi

	# create nuclei output dir if not exist
	if [ ! -d ${_nucleidir} ]; then
		echo "[$(mkdate "dt")]: ${FUNCNAME[0]} [CMD]: mkdir -p ${_nucleidir}"
		mkdir -p -m 700 ${_nucleidir}
		if [ ! -d ${_nucleidir} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [ERROR]: No such directory, (${_nucleidir})"
			exit -255
		fi
	fi

	# check for exsiting output files
	chk_files=(${_dscan_xml} ${_pscan_xml} ${_pscan_targets} ${_nuclei_targets})
	for _file in "${chk_files[@]}"; do
		if [ -f ${_file} ]; then
			echo "[$(mkdate "dt")] ${FUNCNAME[0]} [WARN]: Found ${_file}, Scan already running?, exit()"
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
	# * Latest version of nmap (from source): Nmap now writes filtered ports into the XML files
	#   this can result in HUGE log files when doing full port scans on a lot of hosts
	#   See: https://github.com/nmap/nmap/commit/38671f22259f87f564403dc6e91c1e4216fdb978
	#   To disable this, comment out line 605 in output.cc and recompile:
	#       output.cc:605    //output_rangelist_given_ports(LOG_XML, currentr->ports, currentr->count);
	# * Silent option -v0
	#   https://github.com/nmap/nmap/pull/265
	###############
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: START"

	#------------------------------------------------------------------------------------#
	# Nmap discovery scan
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nmap discovery scan, Starting..."
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Logfile (${_dscan_xml})"

		${_nmap} \
			-v0 -n -sn \
			-PS21-23,25,53,80,110-111,135,139,143,161,443,445,993,995,1723,3306,3389,5900,8080 \
			-PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 \
			--min-parallelism 100 --min-hostgroup 100 --min-rate 20000 --randomize-hosts --disable-arp-ping --max-retries 2 \
		-iL ${_targetsf} -oX ${_dscan_xml} > /dev/null

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nmap discovery scan, Complete"

	# Create port scan targets file
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Create port scan targets (${_pscan_targets})"
	${_nmapparse} --file ${_dscan_xml} --data-type ip > ${_pscan_targets}

	#------------------------------------------------------------------------------------#
	# Nmap port scan (full port scan)
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nmap port scan, Starting..."
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Logfile (${_pscan_xml})"

		${_nmap} \
			-v0 -sS -p- --open \
			--script=${_nsedir}/ --script-timeout=5 \
			--min-parallelism 100 --min-hostgroup 100 --host-timeout 10m --randomize-hosts \
		-iL ${_pscan_targets} -oX ${_pscan_xml} > /dev/null

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nmap port scan, Complete"

	# Create nuclei targets file (nmap httpx.nse results)
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Create nuclei targets (${_nuclei_targets})"
	${_nmapparse} --file ${_pscan_xml} --data-type httpx > ${_nuclei_targets}

	#------------------------------------------------------------------------------------#
	# Nuclei scan (sends data to elasticsearch)
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nuclei scan, Starting..."

	# Download latest nuclei templates
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Updating ${_nucleitpldir}..."
	_gitcmd=`which git`
	pushd `pwd`
	cd ${_nucleitpldir}/ && ${_gitcmd} pull
	popd

	 ${_nuclei} -silent -no-color -disable-update-check -max-redirects 3 \
		-report-config ${_conffile} -list ${_nuclei_targets} \
		-templates ${_nucleitpldir} -config ${_nucleiconf}

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Nuclei scan, Complete"

	#------------------------------------------------------------------------------------#
	# Scan completed, send nmap logs to elasticsearch
	# Note: Sacn times are saved in the log files, we can import this data at any time
	#------------------------------------------------------------------------------------#
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Sending nmap logs to elasticsearch..."
	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: nmap2es: ${_dscan_xml}"
	${_nmap2es} -c ${_conffile} -t discovery -f ${_dscan_xml}

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: nmap2es: ${_pscan_xml}"
	${_nmap2es} -c ${_conffile} -t portscan -f ${_pscan_xml}

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: Complete"

	echo "[$(mkdate "dt")] ${FUNCNAME[0]}() [INFO]: END"
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

