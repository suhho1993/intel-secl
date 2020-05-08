/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel-secl/v3/pkg/hvs"
	commLog "intel-secl/v3/pkg/lib/common/log"
	"os"
	"os/user"
	"strconv"
)

var defaultLog = commLog.GetDefaultLogger()

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(LogFile, 0664)

	httpLogFile, err = os.OpenFile(HttpLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(HttpLogFile, 0664)

	secLogFile, err = os.OpenFile(SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(SecurityLogFile, 0664)

	hvsUser, err := user.Lookup(ServiceUserName)
	if err != nil {
		defaultLog.Errorf("Could not find user '%s'", ServiceUserName)
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(hvsUser.Uid)
	if err != nil {
		defaultLog.Errorf("Could not parse hvs user uid '%s'", hvsUser.Uid)
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(hvsUser.Gid)
	if err != nil {
		defaultLog.Errorf("Could not parse hvs user gid '%s'", hvsUser.Gid)
		return nil, nil, nil, err
	}

	err = os.Chown(HttpLogFile, uid, gid)
	if err != nil {
		defaultLog.Errorf("Could not change file ownership for file: '%s'", HttpLogFile)
		return nil, nil, nil, err
	}
	err = os.Chown(SecurityLogFile, uid, gid)
	if err != nil {
		defaultLog.Errorf("Could not change file ownership for file: '%s'", SecurityLogFile)
	}
	err = os.Chown(LogFile, uid, gid)
	if err != nil {
		defaultLog.Errorf("Could not change file ownership for file: '%s'", LogFile)
		return nil, nil, nil, err
	}

	return
}

func main() {
	l, h, s, err := openLogFiles()
	var app *hvs.App
	if err != nil {
		app = &hvs.App{
			LogWriter: os.Stdout,
		}
	} else {
		defer l.Close()
		defer h.Close()
		defer s.Close()
		app = &hvs.App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
