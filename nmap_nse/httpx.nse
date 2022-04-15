--
-- [/csh:]> date "+%D"
-- 04/11/22
-- https://github.com/c-sh0
--
local stdnse = require "stdnse"
local table = require "table"

description = [[
httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.
https://github.com/projectdiscovery/httpx
]]
--
-- Reason for this script?
--  : https://github.com/nmap/nmap/issues/2395
--
-- Requires httpx
-- nmap target --script=httpx --script-args httpx_bin=/path/to/httpx
--
-- @output
-- Nmap scan report for dev.lan (192.168.1.10)
-- Host is up (0.000048s latency).
-- PORT     STATE SERVICE
-- 5601/tcp open  unknown
-- | httpx:
-- |_  http://192.168.1.10:5601 [302] [/login?next=%2F] [] [Elasticsearch,Kibana,Node.js]
--
--
author = "c-sh0"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

-- Script is executed for any TCP port
portrule = function(host, port)
	if port.protocol == "tcp" then
		return true
	end
	return false
end

action = function(host, port)
	local httpx_bin = stdnse.get_script_args({'httpx_bin', 'path'}) or '/root/go/bin/httpx'
	local httpx_target = host.targetname or host.ip
	local httpx_cmd = ""..httpx_bin.." -no-color -random-agent -status-code -tech-detect -location -web-server -silent -p "..port.number.." <<< "..httpx_target..""
        local resp_table = stdnse.output_table()

        local handle = io.popen(httpx_cmd)
	local result = handle:read("*a")
	handle:close()

	if(result == nil or result == '') then
		return nil
	end

	stdnse.print_debug(1, ("%s:HTTPX TARGET: %s:%s"):format(SCRIPT_NAME, httpx_target, port.number))
	stdnse.print_debug(1, ("%s:HTTPX CMD: %s"):format(SCRIPT_NAME, httpx_cmd))
	stdnse.print_debug(1, ("%s:HTTPX RESULT: %s"):format(SCRIPT_NAME, result))

	table.insert(resp_table,("%s"):format(result))
	return resp_table
end
