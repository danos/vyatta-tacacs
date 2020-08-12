#!/usr/bin/python3

# Module: show-tacplus-status.py
#
# Copyright (c) 2018-2020 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2015-2016 Brocade Comunications Systems, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: Script to retrieve and print tacacs+ details from
#              tacplusd over d-bus.
#
# **** End License ****

import socket

from vyatta import tacplus
from vyatta.tacplus import utils

envFile = "/var/run/tacplus.env"

class TacacsServer (object):
    def __init__(self, addr, port, src,
                       authen_requests, authen_replies,
                       author_requests, author_replies,
                       acct_requests, acct_replies,
                       unknown_replies,
                       failed_connects, active, hold_down):
        self.addr = addr
        self.port = port
        self.src = src
        self.authen_requests = authen_requests
        self.authen_replies = authen_replies
        self.author_requests = author_requests
        self.author_replies = author_replies
        self.acct_requests = acct_requests
        self.acct_replies = acct_replies
        self.unknown_replies = unknown_replies
        self.failed_connects = failed_connects
        self.hold_down = int(hold_down)

        if int(active) == 1:
            self.active = True
        else:
            self.active = False

    def getAddr(self):
        return self.addr

    def getPort(self):
        return self.port

    def getSrc(self):
        return self.src

    def getAuthenRequests(self):
        return self.authen_requests

    def getAuthenReplies(self):
        return self.authen_replies

    def getAuthorRequests(self):
        return self.author_requests

    def getAuthorReplies(self):
        return self.author_replies

    def getAcctRequests(self):
        return self.acct_requests

    def getAcctReplies(self):
        return self.acct_replies

    def getUnknownReplies(self):
        return self.unknown_replies

    def getFailedConnects(self):
        return self.failed_connects

    def isActive(self):
        return self.active

    def getHoldDown(self):
        return self.hold_down

def addServer(tacacsServer):
    allServers.append(tacacsServer)

def getVRFName():
    vrfName = ''
    env = open(envFile)
    line = env.readline().rstrip('\n')
    if line:
        vrf = line.split('=')
        vrfName = vrf[1];
    env.close()
    return vrfName

def printEachServer(offline_remaining):
    output = f'Routing-instance: {getVRFName()}\n'

    if offline_remaining > 0:
        output += f'Offline timer active, expiring in: {offline_remaining}s\n'

    output += '\n'
    for server in allServers:
        output += 'Server address: ' + server.getAddr()

        if server.isActive():
            output += ' (active)\n'
        else:
            output += '\n'

        port = server.getPort()
        output += 'Server port: ' + port + '\n'

        src = server.getSrc()
        if src:
            try:
                socket.getaddrinfo(src, 0, 0, 0, 0, socket.AI_NUMERICHOST)
            except socket.gaierror:
                # src is an interface
                src = "from " + src
            except Exception:
                pass

            output += 'Source address: ' + src + '\n'

        authen_requests = server.getAuthenRequests()
        authen_replies = server.getAuthenReplies()
        output += 'Authentication requests/replies: '\
                   + str(authen_requests) + '/'\
                   + str(authen_replies) + '\n'

        author_requests = server.getAuthorRequests()
        author_replies = server.getAuthorReplies()
        output += 'Authorization requests/replies: '\
                   + str(author_requests) + '/'\
                   + str(author_replies) + '\n'

        acct_requests = server.getAcctRequests()
        acct_replies = server.getAcctReplies()
        output += 'Accounting requests/replies: '\
                   + str(acct_requests) + '/'\
                   + str(acct_replies) + '\n'

        # Discard unknown replies in the statistics for now.

        failed_connects = server.getFailedConnects()
        output += 'Failed connects: ' + failed_connects + '\n'

        hold_down = server.getHoldDown()
        if hold_down > 0:
            output += "Hold down timer active, expiring in: " + str(hold_down) + "s\n"

        output += '\n'
    print(output)


####### BEGIN #######
allServers = [] # TacacsServer

try:
    offline_remaining, status_list = tacplus.Daemon().get_status()
except tacplus.DaemonNotRunning as e:
    utils.print_err("Tacplus daemon is not running.")
    exit(1)
except Exception as e:
    utils.print_err(e)
    exit(1)

for vals in status_list:
    split_vals = vals.split(',')
    ip = split_vals[0]
    port = split_vals[1]
    src = split_vals[2]
    authen_requests = split_vals[3]
    authen_replies = split_vals[4]
    author_requests = split_vals[5]
    author_replies = split_vals[6]
    acct_requests = split_vals[7]
    acct_replies = split_vals[8]
    unknown_replies = split_vals[9]
    failed_connects = split_vals[10]
    active = split_vals[11]
    hold_down = split_vals[12]

    tacacsServer = TacacsServer(ip, port, src,
                                authen_requests, authen_replies,
                                author_requests, author_replies,
                                acct_requests, acct_replies,
                                unknown_replies,
                                failed_connects, active, hold_down)
    addServer(tacacsServer)

if allServers:
    printEachServer(offline_remaining)
else:
    print('No TACACS+ servers are enabled')
