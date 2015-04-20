local http = require "http"
local stdnse = require "stdnse"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
description = [[Attempts to detect webcams AXIS vulnerable to unauthenticated access to the video stream by queryingthe URI "/axis-cgi/jpg/image.cgi".]]
categories = {"vuln", "exploit"}
author = "Bikash Dash(0xfb)"
portrule = shortport.http
action = function(host, port)
        local uri = "/axis-cgi/jpg/image.cgi"
        local _, status_404, resp_404 = http.identify_404(host,port)
        if status_404 == 200 then
                stdnse.print_debug(1, "%s: Web server returns ambiguous response. Axis webcams return standard 404 status responses. Exiting.", SCRIPT_NAME)
                return
        end
        stdnse.print_debug(1, "%s: HTTP HEAD %s", SCRIPT_NAME,uri)
        local resp = http.head(host, port, uri)
        if resp.status and resp.status == 200 then
                return string.format("Axis video feed is unprotected:http://%s/axis-cgi/jpg/image.cgi ", host.ip)
        end
end


