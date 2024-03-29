// Copyright (c) 2018-2020 AT&T Intellectual Property.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/json"
	"fmt"
	"github.com/danos/aaa"
	"github.com/danos/utils/pathutil"
	"log"
	"log/syslog"
	"os"
	"os/user"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus"
)

const AAAPluginsCfgfile = "/etc/aaa-plugins/tacplus.json"

type PluginConfig struct {
	Enabled        bool `json:"enabled"`
	Debug          bool `json:"debug"`
	CmdAcctOptions struct {
		StartRecords bool `json:"start-records"`
	} `json:"command-accounting-options"`
	CmdAuthzOptions struct {
		Service string `json:"service"`
	} `json:"command-authorization-options"`
}

type plugin struct {
	cfg      PluginConfig
	conn     *dbus.Conn
	busObj   dbus.BusObject
	busMutex sync.Mutex
}

type task struct {
	p     *plugin
	user  *user.User
	tty   string
	rhost string
	args  map[string]string
	path  []string
}

func (p *plugin) newTask() task {
	t := task{}
	t.p = p
	t.args = make(map[string]string)
	return t
}

const (
	pluginName = "tacplus"
	logPrefix  = "[tacplus]"

	getAcctTaskIdMethod = "get_account_task_id"
	accountSendMethod   = "cmd_account_send"
	authorSendMethod    = "cmd_author_send"

	tacplusGroup           = "vyatta.system.user.tacplus"
	tacplusDBusInterface   = "net.vyatta.tacplus"
	tacplusDBusDestination = "net.vyatta.tacplus"
	tacplusDBusObjectPath  = "/net/vyatta/tacplus"
	tacplusGetAcctTaskId   = tacplusDBusInterface + "." + getAcctTaskIdMethod
	tacplusAccountSend     = tacplusDBusInterface + "." + accountSendMethod
	tacplusAuthorSend      = tacplusDBusInterface + "." + authorSendMethod

	argProtocol  = "protocol"
	argService   = "service"
	argStartTime = "start_time"
	argStopTime  = "stop_time"
	argTaskId    = "task_id"
	argTimezone  = "timezone"

	tacplusMandatoryAvSep = "="

	tacplusCouldNotSatisfyMsg = "Unable to satisfy response from authorization service"

	/* https://tools.ietf.org/html/draft-grant-tacacs-02 */
	TAC_PLUS_AUTHOR_STATUS_PASS_ADD  = 0x01
	TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
	TAC_PLUS_AUTHOR_STATUS_ERROR     = 0x11

	TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
	TAC_PLUS_ACCT_STATUS_ERROR   = 0x02
	TAC_PLUS_ACCT_STATUS_FOLLOW  = 0x21

	TAC_PLUS_ACCT_FLAG_START = 0x02
	TAC_PLUS_ACCT_FLAG_STOP  = 0x04
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

// Note: this method must be called with p.busMutex held
func (p *plugin) openBusConn() error {
	if p.conn != nil {
		return nil
	}

	c, err := dbus.SystemBusPrivate()
	if err != nil {
		return fmt.Errorf("Failed to connect to D-Bus System Bus: %s", err)
	}

	err = c.Auth(nil)
	if err != nil {
		return fmt.Errorf("Failed to authenticate to D-Bus System Bus: %s", err)
	}

	err = c.Hello()
	if err != nil {
		return fmt.Errorf("Hello on D-Bus System Bus failed: %s", err)
	}

	p.conn = c
	p.busObj = p.conn.Object(tacplusDBusDestination,
		dbus.ObjectPath(tacplusDBusObjectPath))
	return nil
}

// Note: this method must be called with p.busMutex held
func (p *plugin) closeBusConn() error {
	err := p.conn.Close()
	p.conn = nil
	return err
}

func (p *plugin) Setup() error {
	p.loadCfg()

	p.busMutex.Lock()
	err := p.openBusConn()
	p.busMutex.Unlock()

	if err != nil {
		p.log("Continuing after error on plugin setup: %s", err)
	}
	return nil
}

// Note: this method must be called with p.busMutex held
func (p *plugin) restart() error {
	if err := p.closeBusConn(); err != nil {
		p.log(fmt.Sprintf("Error closing bus connection on restart: %s", err))
	}
	return p.openBusConn()
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

func dbusMethodCallError(method string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("D-Bus %s failed: %s", method, err)
}

func (p *plugin) retryOnBusClosedErr(fn func() error, onClosedFn func()) error {
	p.busMutex.Lock()
	defer p.busMutex.Unlock()
	err := p.openBusConn()
	if err != nil {
		return err
	}

	err = fn()
	if err == dbus.ErrClosed {
		if onClosedFn != nil {
			onClosedFn()
		}
		err = p.restart()
		if err == nil {
			err = fn()
		}
	}

	return err
}

func (p *plugin) doAccountSend(
	username,
	tty,
	rhost string,
	args map[string]string,
	path []string,
	flags int32,
) error {
	/*
	 * The return value indicating success/failure of the accounting transaction is
	 * not particularly useful. We would simply log it but failures are already logged
	 * by the TACACS+ provider so it's fairly pointless. Therefore to help with scale
	 * we call account_send() asynchronously and discard the reply.
	 *
	 * "isssa{ss}as" -> flags, username, tty, rhost, array of attribute/value string pairs,
	 *                  array of command args
	 */
	call := p.busObj.Go(tacplusAccountSend, dbus.FlagNoReplyExpected, nil,
		flags, username, tty, rhost, args, path)
	return call.Err
}

func (p *plugin) accountSend(
	user *user.User,
	tty,
	rhost string,
	args map[string]string,
	path []string,
	flags int32,
) error {

	err := p.retryOnBusClosedErr(
		func() error {
			return p.doAccountSend(user.Username, tty, rhost, args, path, flags)
		},
		func() {
			p.log("D-Bus connection closed error on attempt to account command %v "+
				"for user %s (%s)", path, user.Username, user.Uid)
		})

	if err != nil {
		p.syslog(syslog.LOG_ERR, "Failed to account command %v with context "+
			"%v for user %s (%s): %s", path, args, user.Username, user.Uid, err)
	}
	return dbusMethodCallError(accountSendMethod, err)
}

func (t task) AccountStart() error {
	// Always cache the start time, if the start record fails we can
	// still include it in the stop record.
	t.args[argStartTime] = strconv.FormatInt(time.Now().Unix(), 10)

	if !t.p.cfg.CmdAcctOptions.StartRecords {
		t.p.debug("Command accounting start records are not enabled")
		return nil
	}

	if _, exists := t.args[argTaskId]; !exists {
		return fmt.Errorf("Unable to send accounting start record without task ID")
	}
	return t.p.accountSend(t.user, t.tty, t.rhost, t.args, t.path, TAC_PLUS_ACCT_FLAG_START)
}

func (t task) AccountStop(_ *error) error {
	t.args[argStopTime] = strconv.FormatInt(time.Now().Unix(), 10)
	return t.p.accountSend(t.user, t.tty, t.rhost, t.args, t.path, TAC_PLUS_ACCT_FLAG_STOP)
}

func (p *plugin) NewTask(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs, env map[string]string) (aaa.AAATask, error) {

	var err error

	p.debugStack("Accounting request for %v: uid:%v context:%v", path, uid, context)

	t := p.newTask()
	t.path, err = redactPath(path, pathAttrs)
	if err != nil {
		return nil, err
	}

	t.user, err = lookupUserByUid(uid)
	if err != nil {
		return nil, err
	}

	// We must use the same task ID in the accounting start and stop records
	// for a given command execution. Therefore if accounting start records are
	// enabled fetch a task ID ahead of sending the requests.
	//
	// If this fails (unlikely) we will not attempt to issue a start record;
	// otherwise tacplusd will allocate an ID, and there will be a mismatch
	// with the stop record. However in this scenario we can still attempt to
	// issue the stop record (again, tacplusd will allocate an ID for us) and
	// this will include the start_time attribute that would have been used in
	// the suppressed start record.
	if p.cfg.CmdAcctOptions.StartRecords {
		var taskId string
		err := p.retryOnBusClosedErr(func() error {
			return p.busObj.Call(tacplusGetAcctTaskId, 0).Store(&taskId)
		}, nil)
		if err != nil || taskId == "" {
			p.syslog(syslog.LOG_WARNING, "Failed to allocate task ID for TACACS+ "+
				"command accounting - start record will not be issued")
		} else {
			t.args[argTaskId] = taskId
		}
	}

	t.args[argService] = "shell"
	t.args[argProtocol] = context
	t.args[argTimezone] = "UTC"

	/* Best effort */
	t.tty, _ = env["tty"]
	t.rhost = ""

	return t, nil
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

	return p.accountSend(user, ttyName, rhost, args, path, TAC_PLUS_ACCT_FLAG_STOP)
}

func (p *plugin) doAuthorSend(
	username,
	tty,
	rhost string,
	args map[string]string,
	path []string,
) (int32, map[string]string, error) {
	var respType int32
	var avDict map[string]string

	/* "sssa{ss}as" -> username, tty, rhost, array of attribute/value string pairs
	 *                 array of command args
	 */
	err := p.busObj.Call(tacplusAuthorSend, 0, username, tty, rhost,
		args, path).Store(&respType, &avDict)

	return respType, avDict, err
}

func (p *plugin) authorSend(
	user *user.User,
	tty,
	rhost string,
	args map[string]string,
	path []string,
) (int32, map[string]string, error) {

	var respType int32
	var avDict map[string]string
	err := p.retryOnBusClosedErr(
		func() error {
			var err error
			respType, avDict, err = p.doAuthorSend(user.Username, tty, rhost, args, path)
			return err
		},
		func() {
			p.log("D-Bus connection closed error on attempt to authorize command %v "+
				"for user %s (%s)", path, user.Username, user.Uid)
		})

	if err != nil {
		p.syslog(syslog.LOG_ERR, "Failed to authorize command %v with context "+
			"%v for user %s (%s): %s", path, args, user.Username, user.Uid, err)
	}
	return respType, avDict, dbusMethodCallError(authorSendMethod, err)
}

func (p *plugin) Authorize(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs) (bool, error) {
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
		argService:  serv,
		argProtocol: context,
	}

	respType, avDict, err := p.authorSend(user, tty, rhost, args, path)
	if err != nil {
		return false, err
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

var AAAPluginV2 plugin
var AAAPluginAPIVersion uint32 = 2
