#!/bin/sh
# ========================================================================================
# Scans a list of targets, send results into elasicsearch.
#
# [/csh:]> date "+%D"
# 05/11/22
#
#-------------
# notes
#-------------
# nmap:
# - Latest version of nmap (from source): Nmap now writes filtered ports into the
#   XML files this could result in large XML logs files when doing full port scans
#   on a lot of hosts.
#   See:
#     https://github.com/nmap/nmap/commit/38671f22259f87f564403dc6e91c1e4216fdb978
#     https://github.com/nmap/nmap/issues/2478
#
#   To disable this, comment out line 605 in output.cc and recompile:
#       output.cc:605
#           //output_rangelist_given_ports(LOG_XML, currentr->ports, currentr->count);
#
# - Silent option -v0
#   https://github.com/nmap/nmap/pull/265
# ========================================================================================
#################
# Help function #
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
# Date function #
#################
mkdate() {
	_dtype=${1}

	if [ "${_dtype}" == 'dt' ]; then
		local _d=`date +"%Y-%m-%d %T.%3N"`

	elif [ "${_dtype}" == 'logf' ]; then
		local _d=`date +"%m%d%Y-%H"`
	fi

	elif [ "${_dtype}" == 'today' ]; then
		local _d=`date +"%m%d%Y"`
	fi

	echo "${_d}"
}

####################
# Log msg function #
####################
wr_mesg() {
	_msg=${1}
	echo "[$(mkdate "dt")]: ${_msg}"
}

######################
# Parseargs function #
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
_datadir="${_rundir}/data"
_confdir="${_rundir}/conf"
_scriptdir="${_rundir}/scripts"
_logdir="${_datadir}/logs"
_configf="${_confdir}/santacruz.yml"

# nmap
_nmap_bin='/usr/local/bin/nmap'
_nmap_rundir="${_rundir}/nmap"
_nmap_logdir="${_logdir}/nmap"
_nmapparse="${_scriptdir}/nmapparse.py"

# httpx
_httpx_bin='/usr/local/bin/httpx'
_httpx_logdir="${_logdir}/httpx"

# nuclei
_nuclei='/usr/local/bin/nuclei'
_nuclei_conf="${_confdir}/nuclei.yml"
_nuclei_logdir="${_logdir}/nuclei"
_nuclei_tpldir="${_datadir}/nuclei-templates"

# send logs to ES script
_sendtoes="${_scriptdir}/sendlog2es.py"

#####################
# Pre-scan function #
#####################
pre_scan() {
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] ${FUNCNAME[0]}(), start"

	# check directories
	chk_dirs=(${_datadir} ${_confdir} ${_scriptdir} ${_nmap_rundir} ${_nuclei_tpldir})
	for _dir in "${chk_dirs[@]}"; do
		if [ ! -d ${_dir} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [ERROR] ${FUNCNAME[0]}(), directory does not exist: ${_dir}"
			exit -255
		fi
	done

	# check files
	chk_files=(${_nmapparse} ${_httpxnse} ${_configf} ${_nucleiconf} ${_sendtoes})
	for _file in "${chk_files[@]}"; do
		if [ ! -f ${_file} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [ERROR] ${FUNCNAME[0]}(), file does not exist: ${_file}"
			exit -255
		fi
	done

	# check for tool installation
	tools=(${_nmap_bin} ${_httpx_bin} ${_nuclei})
	for tool in "${tools[@]}"; do
		if [ ! -f ${tool} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [ERROR] ${FUNCNAME[0]}(), file does not exist: ${_file}"
			exit -255
		fi
	done

	# create log directories if not exist
	log_dirs=(${_logdir} ${_nmap_logdir} ${_httpx_logdir} ${_nuclei_logdir})
	for _dir in "${log_dirs[@]}"; do
		if [ ! -d ${_dir} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [CMD] ${FUNCNAME[0]}(), creating directory: ${_dir}"
			mkdir -p -m 700 ${_dir}
			if [ ! -d ${_dir} ]; then
				wr_mesg "${FUNCNAME[0]}():${LINENO}, [ERROR] ${FUNCNAME[0]}(), unable to create directory: ${_dir}"
				exit -255
			fi
		fi
	done

	wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] ${FUNCNAME[0]}(), end"
}

#################
# Scan function #
#################
run_scan() {
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] ${FUNCNAME[0]}(), start"

	#------------------------------------------------------------------------------------#
	# targets/log file vars
	#------------------------------------------------------------------------------------#
	_dt="$(mkdate "logf")"
	_dscan_log="${_nmap_logdir}/discovery_scan-${_dt}.xml"
	_pscan_log="${_nmap_logdir}/port_scan-${_dt}.xml"
	_httpx_log="${_httpx_logdir}/httpx_scan.${_dt}.json"

	_nmap_excludef="${_datadir}/nmap-excludes.db"
	_nmap_exclude_tmp="${_datadir}/exclude.$RANDOM$$.${_dt}.tmp"

	_nmap_targets="${_nmap_logdir}/nmap-${_dt}.targets"
	_nuclei_targets="${_nuclei_logdir}/nuclei-${_dt}.targets"
	_httpx_targets="${_httpx_logdir}/httpx-${_dt}.targets"


	# check for exsiting output files
	chk_files=(${_dscan_log} ${_pscan_log} ${_nmap_targets} ${_httpx_log} ${_httpx_targets})
	for _file in "${chk_files[@]}"; do
		if [ -f ${_file} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [WARN] ${FUNCNAME[0]}, found: ${_file}, Scan already running?, exit()"
			exit -255
		fi
	done

	# create nmap excludes file if not exist
	if [ ! -f ${_nmap_excludef} ]; then
		wr_mesg "${FUNCNAME[0]}():${LINENO}, [CMD] ${FUNCNAME[0]}, create: ${_nmap_excludef}"
		touch ${_nmap_excludef}

		if [ ! -f ${_nmap_excludef} ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [ERROR] ${FUNCNAME[0]}, file does not exist: ${_nmap_excludef}"
			exit -255
		fi
	fi

	#------------------------------------------------------------------------------------#
	# Nmap discovery scan
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [NMAP] discovery_scan, started ..."

		${_nmap_bin} \
			-v0 -sn \
			-PS21-23,25,53,80,110-111,135,139,143,161,443,445,587,993,995,1025,1723,3306,3389,5666,5900,8080,8443,9090 \
			-PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 \
			--min-parallelism 32 --min-rate 10000 --randomize-hosts --disable-arp-ping --max-retries 4 \
		-iL ${_targetsf} --excludefile ${_nmap_excludef} -oX ${_dscan_log} > /dev/null

	 wr_mesg "${FUNCNAME[0]}():${LINENO}, [NMAP] discovery_scan, completed, log: ${_dscan_log}"

	#------------------------------------------------------------------------------------#
	# Create port scan targets file
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [NMAP] port_scan, creating targets file: ${_nmap_targets}"
	${_nmapparse} --file ${_dscan_log} --output ip > ${_nmap_targets}

	#------------------------------------------------------------------------------------#
	# Nmap port discovery scan
	#------------------------------------------------------------------------------------#
	# Use custom nmap-services file for default port scanning. (--datadir)
	# https://nmap.org/book/nmap-services.html
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [NMAP] port_scan, started ..."

		${_nmap_bin} -v0 -sS --open --datadir ${_nmap_rundir} \
			--min-parallelism 64 --min-hostgroup 128 --min-rate 10000 --defeat-rst-ratelimit --host-timeout 10m --randomize-hosts \
		-iL ${_nmap_targets} --excludefile ${_nmap_excludef} -oX ${_pscan_log} > /dev/null

	 wr_mesg "${FUNCNAME[0]}():${LINENO}, [NMAP] port_scan, completed, log: ${_pscan_log}"

	#------------------------------------------------------------------------------------#
	# Ferret out hosts with an IDS and exclude them from future scans. If the report
	# shows hosts with 100 or more ports as open, This is a pretty good indication that
	# there is a security mechanism in place for that host.
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] searching for hosts with open ports >= 100 ..."
	${_nmapparse} --file ${_pscan_log} --output pcount -gt 50 | cut -d, -f2 | sort -t. -k3,3n -k4,4n > ${_nmap_exclude_tmp}

	for _ip_addr in `cat ${_nmap_exclude_tmp}`; do
		_found=`grep -c -w ${_ip_addr} ${_nmap_excludef}`
		if [ ${_found} -eq 0 ]; then
			wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] adding ${_ip_addr} to ${_nmap_excludef}"
			echo "${_ip_addr}" >> ${_nmap_excludef}
		fi
	done
	# delete tmp file
	rm -f ${_nmap_exclude_tmp}

	#------------------------------------------------------------------------------------#
	# httpx scan
	#------------------------------------------------------------------------------------#
	# Parse nmap port scan results, find ports running http services
	# --skip-gt (Skip hosts who report >= 100 open ports, chances are that there is a
	# security mechanism in place for that host)
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [HTTPX] httpx_scan, creating targets, file: ${_httpx_targets}"
	${_nmapparse} --file ${_pscan_log} --output httpx --skip-gt 100 > ${_httpx_targets}

	#------------------------------------------------------------------------------------#
	# Note: Golang is set to depricate unsupported tls versions in furture release.
	# see this discussion:
	# https://github.com/projectdiscovery/httpx/discussions/633
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [HTTPX] httpx_scan, started ..."
	export GODEBUG=tls10default=1
	${_httpx_bin} -silent -nc -sc -td -tls-grab -title -fhr -ec -location -web-server -jarm -maxr 5 -timeout 3 -list ${_httpx_targets} -json > ${_httpx_log}

	wr_mesg "${FUNCNAME[0]}():${LINENO}, [HTTPX] httpx_scan, completed, log: ${_httpx_log}"

	#------------------------------------------------------------------------------------#
	# Create nuclei targets from httpx results
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [NUCLEI] nuclei_scan, creating targets, file: ${_nuclei_targets}"
	cat ${_httpx_log} | jq '.url' | sed -e 's/"//g' > ${_nuclei_targets}


	#------------------------------------------------------------------------------------#
	# Nuclei scan
	#------------------------------------------------------------------------------------#
	#------------------------------------------------------------------------------------#

	#------------------------------------------------------------------------------------#
	# Send scan logs to Elasticsearch
	#------------------------------------------------------------------------------------#
	wr_mesg "${FUNCNAME[0]}():${LINENO}, [LOG2ES] send_logs, sending ${_dscan_log} to Elasticsearch ..."
        ${_sendtoes} -c ${_configf} -f ${_dscan_log} -t discovery

	wr_mesg "${FUNCNAME[0]}():${LINENO}, [LOG2ES] send_logs, sending ${_pscan_log} to Elasticsearch ..."
        ${_sendtoes} -c ${_configf} -f ${_pscan_log} -t portscan

	wr_mesg "${FUNCNAME[0]}():${LINENO}, [LOG2ES] send_logs, sending ${_httpx_log} to Elasticsearch ..."
        ${_sendtoes} -c ${_configf} -f ${_httpx_log} -t httpx

	wr_mesg "${FUNCNAME[0]}():${LINENO}, [INFO] ${FUNCNAME[0]}(), end"
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

