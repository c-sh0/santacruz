--
-- [/csh:]> date "+%D"
-- 04/11/22
-- https://github.com/c-sh0
--
local stdnse = require "stdnse"
local table = require "table"

description = [[
httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryable http library,
it is designed to maintain the result reliability with increased threads.
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
-- Nmap scan report for dev.lan (127.0.0.1)
-- Host is up (0.000048s latency).
-- PORT     STATE SERVICE
-- 5601/tcp open  unknown
-- |_httpx: http://127.0.0.1:5601 [302] [/login?next=%2F] [Elasticsearch,Kibana,Node.js]
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
	local httpx_bin = stdnse.get_script_args({'httpx_bin', 'path'}) or '/usr/local/bin/httpx'
	local httpx_target = host.targetname or host.ip
	local httpx_cmd = ""..httpx_bin.." -silent -nc -sc -td -fhr -ec -maxr 1 -random-agent -location -web-server -timeout 2 -retries 3 -p "..port.number.." <<< "..httpx_target..""
	local resp_table = stdnse.output_table()

	local handle = io.popen(httpx_cmd)
	local result = handle:read("*a")
	handle:close()

	-- Remove empty "[]" responses
	-- Replace multiple spaces with a single space
	res = result:gsub("%[%]", "")
	result = res:gsub("%s+"," ")

	if(result == nil or result == '') then
		return nil
	end

	stdnse.print_debug(1, ("%s:HTTPX TARGET: %s:%s"):format(SCRIPT_NAME, httpx_target, port.number))
	stdnse.print_debug(1, ("%s:HTTPX CMD: %s"):format(SCRIPT_NAME, httpx_cmd))
	stdnse.print_debug(1, ("%s:HTTPX RESULT: %s"):format(SCRIPT_NAME, result))

	return result
end
