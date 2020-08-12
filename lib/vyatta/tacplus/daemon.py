# Copyright (c) 2020 AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

import dbus

TACPLUS_DAEMON      = "net.vyatta.tacplus"
TACPLUS_DAEMON_PATH = "/net/vyatta/tacplus"

class DaemonNotRunning(Exception):
    pass

def _is_not_running_err(err):
    return err.endswith((".NameHasNoOwner", ".ServiceUnknown"))

def Daemon():
    """ Returns a proxy object for interacting with tacplusd """

    bus = dbus.SystemBus()
    try:
        return dbus.Interface(
            bus.get_object(TACPLUS_DAEMON, TACPLUS_DAEMON_PATH),
            TACPLUS_DAEMON)
    except dbus.exceptions.DBusException as e:
        if _is_not_running_err(e.get_dbus_name()):
            raise DaemonNotRunning("TACACS+ daemon is not running")
        raise
