#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Guest Account PAM Module for Pardus Linux """

import os
import pwd
import sys
import tempfile
import subprocess
import ConfigParser
import shutil
import grp

def log(text):
    """ Log Function. """

    sys.stdout.write(text)
    sys.stdout.flush()

def auth_return(pamh, level, home_dir=""):
    """ Return Function. """

    if level >= 2:
        shutil.rmtree(home_dir)

    if level >= 3:
        out = subprocess.Popen(["umount %s" % home_dir], shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out.wait()

    if level == 0:
        return pamh.PAM_SUCCESS

    if level == -1:
        return pamh.PAM_AUTHINFO_UNAVAIL

    if level == -2:
        return pamh.PAM_MAXTRIES

    if level == 1 or level > 2:
        return pamh.PAM_AUTH_ERR

def pam_sm_authenticate(pamh, flags, argv):
    """ Authentication Function.

        If username is _guest_, with this function \
        guest user will be authenticated without \
        password.
    """

    try:
        pwd.getpwnam(pamh.get_user(None))
        return auth_return(pamh, -1)
    except KeyError:
        pass

    try:
        debugging = (argv[1] == 'debug')
    except IndexError:
        debugging = False

    try:
        config = ConfigParser.ConfigParser()
        config.read('/etc/security/guestlogin.conf')
        guest_enabled = config.get('guest', 'enabled')
        if guest_enabled == '':
            guest_enabled = "true"
        guest_name = config.get('guest', 'guestname')
        if guest_name == '':
            guest_name = "guest"
        guest_limit = config.get('guest', 'guestlimit')
        if guest_limit == '':
            guest_limit = 5
        guest_home_dir_size = config.get('guest', 'homedirsize')
        if guest_home_dir_size == '':
            guest_home_dir_size = 300
        guest_group = config.get('guest', 'guestgroup')
        if guest_group == '':
            guest_group = "guests"

    except ConfigParser.Error:
        guest_enabled = "true"
        guest_name = "guest"
        guest_limit = 5
        guest_home_dir_size = 300
        guest_group = "guests"
        if debugging and pamh.get_user(None) == guest_name:
            log("Unable to read config file at /etc/security/guestlogin.\
conf, using default values.\n")

    if guest_enabled == "false":
        return auth_return(pamh, 1)

    if pamh.get_user(None) == guest_name:
        users = [x.pw_name for x in pwd.getpwall()]
        i = 1
        while "%s%s" % (guest_name, i) in users:
            i = i + 1
            if (i > guest_limit):
                if debugging:
                    log("Guest User limit reached! Unable to create \
another guest user account.\n")
                return auth_return(pamh, -2)

        username = "%s%s" % (guest_name, i)
        pamh.user = username
        try:
            grp.getgrnam(guest_group)
        except KeyError:
            if debugging:
                log("No group found named as %s, it will be \
created.\n" % guest_group)
            out = subprocess.Popen(["groupadd %s" % guest_group], \
                    shell=True, stdout=subprocess.PIPE, \
                    stderr=subprocess.PIPE)
            if out.wait() != 0:
                if debugging:
                    log("Creating group %s has been failed!" % guest_group)
                return auth_return(pamh, -1)
        try:
            home_dir = tempfile.mkdtemp(prefix='%s.' % username)
        except IOError:
            if debugging:
                log("No usable temporary directory name found")
            return auth_return(pamh, -2)

        if debugging:
            log("%s has been created successful with mktemp.\n" % home_dir)

        out = subprocess.Popen(["mount -t tmpfs -o size=%sm -o mode=711 \
                -o noexec none %s" % (guest_home_dir_size, home_dir)], \
                shell=True)
        if out.wait() != 0:
            if debugging:
                log("Unable to mount %s" % home_dir)
            return auth_return(pamh, -2)

        if not os.path.ismount(home_dir):
            if debugging:
                log("Mount error! Unable to ismount(%s)" % home_dir)
            return auth_return(pamh, 2, home_dir)

        if debugging:
            log("%s has mounted as tmpfs\n" % home_dir)

        out = subprocess.Popen(["useradd -m -d %s/home -g %s %s" % \
                (home_dir, guest_group, username)], shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if out.wait() != 0:
            if debugging:
                log("Unable to add user %s to system\n" % username)
            return auth_return(pamh, -2)

        try:
            pwd.getpwnam(username)

        except KeyError:
            if debugging:
                log("User %s not found! Unable to getpwnam(%s)\n" % \
                        (username, username))
            return auth_return(pamh, 3, home_dir)

        if debugging:
            log("%s has been created successfully\n" % username)

        return auth_return(pamh, 0)

    else:
        return auth_return(pamh, -1)

def pam_sm_setcred(pamh, flags, argv):
    """ Set Cred. """

    try:
        debugging = (argv[1] == 'debug')

    except IndexError:
        debugging = False

    try:
        config = ConfigParser.ConfigParser()
        config.read('/etc/security/guestlogin.conf')
        guest_enabled = config.get('guest', 'enabled')
        if guest_enabled == '':
            guest_enabled = "true"
        guest_name = config.get('guest', 'guestname')
        if guest_name == '':
            guest_name = "guest"

    except ConfigParser.Error:
        guest_enabled = "true"
        guest_name = "guest"

        if debugging and pamh.get_user(None) == guest_name:
            log("Unable to read config file at /etc/security/guestlogin.\
conf, using default values.\n")

    if guest_enabled == "false":
        return auth_return(pamh, 1)

    if pamh.get_user(None).find(guest_name) == -1:
        return auth_return(pamh, -1)

    else:
        return auth_return(pamh, 0)

def pam_sm_open_session(pamh, flags, argv):
    """ Open Session """
    return auth_return(pamh, 0)

def pam_sm_close_session(pamh, flags, argv):
    """ Close Session, if user is guest \
destroy it but it seems quite dangerous"""

    try:
        if (argv[1] == 'debug'):
            debugging = True
    except KeyError:
        debugging = False
    try:
        config = ConfigParser.ConfigParser()
        config.read('/etc/security/guestlogin.conf')
        guest_name = config.get('guest', 'guestname')
        guest_enabled = config.get('guest', 'enabled')
        if guest_enabled == '':
            guest_enabled = 'true'
        if guest_name == '':
            guest_name = "guest"

    except ConfigParser.Error:
        guest_enabled = "true"
        guest_name = "guest"
        if debugging and pamh.get_user(None).find(guest_name) != -1:
            log("Unable to read config file at /etc/security/guestlogin.\
conf, using default values.\n")

    if guest_enabled == 'false':
        return auth_return(pamh, 1)

    if pamh.get_user(None).find(guest_name) != -1:
        username = pamh.get_user(None)
        _home_dir = pwd.getpwnam(username).pw_dir
        home_dir = _home_dir[0:_home_dir.rfind('/')+1]
        out = subprocess.Popen(["skill -KILL -u %s" % username], shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out.wait()

        if debugging:
            log("%s's all processes are killed\n" % username)


        out = subprocess.Popen(["umount %s" % home_dir], shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out.wait()

        if debugging:
            log("%s successfully unmounted\n" % home_dir)

        out = subprocess.Popen(["userdel -f %s" % username], shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out.wait()

        if debugging:
            log("user %s has been deleted\n" % username)

        shutil.rmtree(home_dir)

        if debugging:
            log("folder %s has been deleted\n" % home_dir)

    return auth_return(pamh, 0)
