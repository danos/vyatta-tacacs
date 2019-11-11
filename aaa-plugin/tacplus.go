// Copyright (c) 2018-2019 AT&T Intellectual Property.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/json"
	"fmt"
	"github.com/danos/utils/pathutil"
	"log"
	"log/syslog"
	"os"
	"os/user"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus"
)

var busObj dbus.BusObject
var isEnabled bool

const AAAPluginsCfgfile = "/etc/aaa-plugins/tacplus.json"

type PluginConfig struct {
	Enabled         bool `json:"enabled"`
	Debug           bool `json:"debug"`
	CmdAuthzOptions struct {
		Service string `json:"service"`
	} `json:"command-authorization-options"`
}

type plugin struct {
	cfg PluginConfig
}

const (
	pluginName = "tacplus"
	logPrefix  = "[tacplus]"

	tacplusGroup           = "vyatta.system.user.tacplus"
	tacplusDBusInterface   = "net.vyatta.tacplus"
	tacplusDBusDestination = "net.vyatta.tacplus"
	tacplusDBusObjectPath  = "/net/vyatta/tacplus"
	tacplusAccountSend     = tacplusDBusInterface + ".cmd_account_send"
	tacplusAuthorSend      = tacplusDBusInterface + ".cmd_author_send"

	tacplusMandatoryAvSep = "="

	tacplusCouldNotSatisfyMsg = "Unable to satisfy response from authorization service"

	/* https://tools.ietf.org/html/draft-grant-tacacs-02 */
	TAC_PLUS_AUTHOR_STATUS_PASS_ADD  = 0x01
	TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
	TAC_PLUS_AUTHOR_STATUS_ERROR     = 0x11

	TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
	TAC_PLUS_ACCT_STATUS_ERROR   = 0x02
	TAC_PLUS_ACCT_STATUS_FOLLOW  = 0x21

	TAC_PLUS_ACCT_FLAG_STOP = 0x04
)

var ignoredMandatoryArgs = map[string]bool{}

func (p *plugin) debug(fmt string, v ...interface{}) {
	if p.cfg.Debug {
		p.log(fmt, v...)
	}
}

func (p *plugin) debugStack(fmt string, v ...interface{}) {
	if p.cfg.Debug {
		var stackStrBuilder strings.Builder
		stackStrBuilder.Write(debug.Stack())
		p.log(fmt+"\n"+stackStrBuilder.String(), v...)
	}
}

func (p *plugin) log(fmt string, v ...interface{}) {
	log.Printf(logPrefix+" "+fmt, v...)
}

func (p *plugin) syslog(pri syslog.Priority, msgFmt string, v ...interface{}) {
	slog, err := syslog.New(syslog.LOG_AUTH|pri, logPrefix)
	if err != nil {
		// Fallback to alternative logger
		p.log("Failed to connect to syslog: %s", err)
		p.log(msgFmt, v...)
	} else {
		slog.Write([]byte(fmt.Sprintf(msgFmt, v...)))
	}
}

func (p *plugin) loadCfg() {
	var cfg PluginConfig

	f, e := os.Open(AAAPluginsCfgfile)
	if e != nil {
		p.debug("Failed opening plugin config file: %s", e)
		return
	}

	dec := json.NewDecoder(f)
	e = dec.Decode(&cfg)
	if e != nil {
		p.log("Failed to decode plugin config file: %s", e)
		return
	}

	p.cfg = cfg
}

func (p *plugin) Setup() error {
	p.loadCfg()

	conn, err := dbus.SystemBus()
	if err != nil {
		e := fmt.Errorf("Failed to connect to D-Bus System Bus: %s", err)
		return e
	}
	busObj = conn.Object(tacplusDBusDestination, dbus.ObjectPath(tacplusDBusObjectPath))
	return nil
}

func lookupUserByUid(uid uint32) (*user.User, error) {
	user, err := user.LookupId(fmt.Sprintf("%v", uid))
	if err != nil {
		return nil, fmt.Errorf("Could not lookup user id %d: %s", uid, err)
	}
	return user, nil
}

func redactPath(path []string, pathAttrs *pathutil.PathAttrs) ([]string, error) {
	/* Secrets MUST be redacted from the path */
	if pathAttrs == nil || len(path) != len(pathAttrs.Attrs) {
		return []string{}, fmt.Errorf("Unable to redact command")
	}

	/* Redact values for all secret elements in the path */
	rpath := make([]string, len(path))
	for i, v := range pathAttrs.Attrs {
		if v.Secret {
			rpath[i] = "**"
		} else {
			rpath[i] = path[i]
		}
	}

	return rpath, nil
}

func (p *plugin) Account(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs, env map[string]string) error {

	p.debugStack("Accounting request for %v: uid:%v context:%v", path, uid, context)

	path, err := redactPath(path, pathAttrs)
	if err != nil {
		return err
	}

	/* Best effort */
	ttyName, _ := env["tty"]
	rhost := ""

	user, err := lookupUserByUid(uid)
	if err != nil {
		return err
	}

	stop_time := time.Now().Unix()
	args := map[string]string{
		"service":   "shell",
		"protocol":  context,
		"stop_time": strconv.FormatInt(stop_time, 10),
	}

	/*
	 * The return value indicating success/failure of the accounting transaction is
	 * not particularly useful. We would simply log it but failures are already logged
	 * by the TACACS+ provider so it's fairly pointless. Therefore to help with scale
	 * we call account_send() asynchronously and discard the reply.
	 *
	 * "isssa{ss}" -> flags, username, tty, rhost, array of attribute/value string pairs
	 */
	call := busObj.Go(tacplusAccountSend, dbus.FlagNoReplyExpected, nil,
		TAC_PLUS_ACCT_FLAG_STOP, user.Username, ttyName, rhost, args, path)
	if call.Err != nil {
		return fmt.Errorf("D-Bus account_send failed: %s", call.Err)
	}
	return nil
}

func (p *plugin) Authorize(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs) (bool, error) {
	var respType int32
	var avDict map[string]string
	var result bool

	p.debugStack("Authorization request for %v: uid:%v context:%v", path, uid, context)

	path, err := redactPath(path, pathAttrs)
	if err != nil {
		return false, err
	}

	/* Best effort */
	tty := ""
	rhost := ""

	user, err := lookupUserByUid(uid)
	if err != nil {
		return false, err
	}

	serv := p.cfg.CmdAuthzOptions.Service
	if serv == "" {
		serv = "vyatta-exec"
	}
	args := map[string]string{
		"service":  serv,
		"protocol": context,
	}

	/* "sssa{ss}" -> username, tty, rhost, array of attribute/value string pairs */
	err = busObj.Call(tacplusAuthorSend, 0, user.Username,
		tty, rhost, args, path).Store(&respType, &avDict)
	if err != nil {
		e := fmt.Errorf("D-Bus author_send failed: %s", err)
		return false, e
	}

	switch respType {
	case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
		result = true
		for name, _ := range avDict {
			nameNoSep := strings.TrimSuffix(name, tacplusMandatoryAvSep)
			if name != nameNoSep {
				if logged, ignored := ignoredMandatoryArgs[nameNoSep]; ignored {
					if !logged {
						p.syslog(syslog.LOG_INFO, "Ignoring mandatory TACACS+ "+
							"attribute '%s' - not supported in this context (this "+
							"message is logged only once)", nameNoSep)
						ignoredMandatoryArgs[nameNoSep] = true
					}
				} else {
					p.syslog(syslog.LOG_WARNING, "Unsupported mandatory TACACS+ "+
						"attribute '%s'", nameNoSep)
					result = false
				}
			}
		}
		if !result {
			err = fmt.Errorf(tacplusCouldNotSatisfyMsg)
		}

	case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
		result = false
		p.syslog(syslog.LOG_WARNING, "Argument replacement "+
			"(TAC_PLUS_AUTHOR_STATUS_PASS_REPL) is not supported")
		err = fmt.Errorf(tacplusCouldNotSatisfyMsg)

	case TAC_PLUS_AUTHOR_STATUS_ERROR:
		result = false
		err = fmt.Errorf("Access to the requested operation denied due to authorisation service failure")

	default:
		result = false
	}

	p.debug("Authorization result for \"%s\": user:%s context:%s -> result:%v", strings.Join(path, " "), user.Username, context, result)

	return result, err
}

func (p *plugin) ValidUser(uid uint32, groups []string) (bool, error) {
	p.debug("ValidUser: %v / %v", uid, groups)
	for _, g := range groups {
		p.debug("ValidUser: %v / %v -> g: %v", uid, groups, g)
		if g == tacplusGroup {
			p.debug("ValidUser: %v / %v -> true", uid, groups)
			return true, nil
		}
	}
	p.debug("ValidUser: %v / %v -> false", uid, groups)
	return false, nil
}

var AAAPluginV1 plugin
var AAAPluginAPIVersion uint32 = 1
