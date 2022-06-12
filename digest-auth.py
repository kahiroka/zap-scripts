# The sendingRequest and responseReceived functions will be called for all
# requests/responses sent/received by ZAP, including automated tools (e.g.
# active scanner, fuzzer, ...)

# Note that new HttpSender scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"

# 'initiator' is the component the initiated the request:
#      1   PROXY_INITIATOR
#      2   ACTIVE_SCANNER_INITIATOR
#      3   SPIDER_INITIATOR
#      4   FUZZER_INITIATOR
#      5   AUTHENTICATION_INITIATOR
#      6   MANUAL_REQUEST_INITIATOR
#      7   CHECK_FOR_UPDATES_INITIATOR
#      8   BEAN_SHELL_INITIATOR
#      9   ACCESS_CONTROL_SCANNER_INITIATOR
#     10   AJAX_SPIDER_INITIATOR
# For the latest list of values see the HttpSender class:
# https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/parosproxy/paros/network/HttpSender.java
# 'helper' just has one method at the moment: helper.getHttpSender() which
# returns the HttpSender instance used to send the request.
#
# New requests can be made like this:
# msg2 = msg.cloneAll() # msg2 can then be safely changed without affecting msg
# helper.getHttpSender().sendAndReceive(msg2, false)
# print('msg2 response code =' + msg2.getResponseHeader().getStatusCode())

# add-on: python scripting 
import subprocess
import commands
import hashlib
import re
import binascii
import os
import org.zaproxy.zap.extension.script.ScriptVars as svars

username = 'user'
password = 'pass'
realm = 'realm'

script = 'digest-auth'

def sendingRequest(msg, initiator, helper):
    if initiator != 1:
        method = msg.getRequestHeader().getMethod()
        m = re.match(r'[^/]+//[^/]+(/.*)', msg.getRequestHeader().getURI().toString())
        uri = m.group(1)
        nonce = svars.getScriptVar(script, 'nonce')
        cnonce = svars.getScriptVar(script, 'cnonce')
        nc = svars.getScriptVar(script, 'nc')
        if nonce != None or cnonce != None or nc != None:
            h1 = hashlib.md5((username+':'+realm+':'+password).encode('utf-8')).hexdigest() #todo: realm
            h2 = hashlib.md5((method+":"+uri).encode('utf-8')).hexdigest()
            nchex = "{:08x}".format(int(nc))
            response = hashlib.md5((h1+":"+nonce+":"+nchex+":"+cnonce+":auth:"+h2).encode('utf-8')).hexdigest()
            authz = "Digest username=\""+username+"\", realm=\""+realm+"\", nonce=\"" + nonce + "\", uri=\""+ uri
            authz += "\", response=\""+ response +"\", qop=auth, nc="+ nchex +", cnonce=\"" + cnonce + "\""
            msg.getRequestHeader().setHeader("Authorization", authz)
            svars.setScriptVar(script, 'nc', "{:n}".format(int(nc)+1))

def responseReceived(msg, initiator, helper):
    if initiator != 1:
        authn = msg.getResponseHeader().getHeader("WWW-Authenticate")
        if authn != None:
            m = re.match(r'.*nonce="([\w\d]+)".*', authn)
            if m != None:
                svars.setScriptVar(script, 'nonce', m.group(1))
                svars.setScriptVar(script, 'nc', '1')
                cnonce = binascii.b2a_hex(os.urandom(8))
                svars.setScriptVar(script, 'cnonce', cnonce)
