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
import time


class ProcessReturnValues:
    """ Just a container of vital information returned by a spawned process. """

    returnCode = -1
    stdOutput = ""
    errOutput = ""

    def __init__(self, rc, so, eo):
        self.returnCode = rc
        self.stdOutput = so
        self.errOutput = eo


def runProcess(args):
    """ Helper function to launch a process and retrieve vital information. """

    try:
        childProcess = subprocess.Popen(args,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        (stdOutput, errOutput) = childProcess.communicate()

    except OSError as (errno, strerror):
        return ProcessReturnValues(errno, "", strerror)

    return ProcessReturnValues(childProcess.returncode, stdOutput, errOutput)




def log(text):
    """ Log Function. """

    sys.stdout.write(text)
    sys.stdout.flush()


def get_next_guest_username(baseName, groupName, maxAccount):

    if maxAccount <= 0:
        raise KeyError

    try:
        grEntry = grp.getgrnam(groupName)
    except KeyError:
        # should never happen...
        raise KeyError

    allEntries = pwd.getpwall()

    validGuestEntries = []
    invalidGuestEntries = []

    for pwEntry in allEntries:
        if pwEntry.pw_name.startswith(baseName) and pwEntry.pw_gid == grEntry.gr_gid:
            if os.path.exists(pwEntry.pw_dir) == False:
                invalidGuestEntries.append(pwEntry)
            else:
                validGuestEntries.append(pwEntry)

    nValidGuestEntries = len(validGuestEntries)
    nInvalidGuestEntries = len(invalidGuestEntries)

    if nValidGuestEntries > maxAccount:
        raise KeyError

    if nInvalidGuestEntries != 0:
        invalidGuestEntries.sort()
        guestEntry = invalidGuestEntries.pop()
        return guestEntry.pw_name

    if len(validGuestEntries) == 0:
        return "%s1" % (baseName)

    # if we're here it means nInvalidGuestEntries == 0 and nValidGuestEntries != 0

    validGuestEntries.sort()

    # let's find a slot within existing guest account

    accountNumber = 1
    for guestEntry in validGuestEntries:
        if guestEntry.pw_name == "%s%d" % (baseName, accountNumber):
            accountNumber = accountNumber + 1
            if accountNumber > maxAccount:
                raise KeyError
        else:
            return "%s%d" % (baseName, accountNumber)

    if accountNumber > maxAccount:
        raise KeyError

    return "%s%d" % (baseName, accountNumber)


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
        debugging = (len(argv) > 1 and argv[1] == 'debug')
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
            log("Unable to read config file at /etc/security/guestlogin.conf, using default values.\n")

    if guest_enabled == "false":
        return auth_return(pamh, 1)

    if pamh.get_user(None) == guest_name:

        # create guest group if not exist
        try:
            grp.getgrnam(guest_group)
        except KeyError:
            if debugging:
                log("No group found named as %s, it will be created.\n" % guest_group)

            processRet = runProcess(["groupadd --system %s" % (guest_group)])
            if processRet.returnCode != 0:
                if debugging:
                    log("'groupadd --system %s' failed errno %d '%s'" % (guest_group, processRet.returnCode, processRet.errOutput))
                return auth_return(pamh, -1)

        if debugging:
            log("group added\n")

        # find out next guest username among existing and not existing, valid and invalid guest username
        try:
            username = get_next_guest_username(guest_name, guest_group, int(guest_limit))
        except KeyError:
            if debugging:
                log("No more slot found for a guest acccount\n")
            return auth_return(pamh, -2)

        if debugging:
            log("username '%s'\n" % (username))

        pamh.user = username

        # create and mount tmpfs home directory
        try:
            home_dir = tempfile.mkdtemp(prefix='%s.' % username)
        except IOError:
            if debugging:
                log("No usable temporary directory name found\n")
            return auth_return(pamh, -2)

        if debugging:
            log("%s has been created successful with mktemp.\n" % home_dir)

        processRet = runProcess(["mount -t tmpfs -o size=%sm -o mode=711 -o noexec none %s" % (guest_home_dir_size, home_dir)])
        if processRet.returnCode != 0:
            if debugging:
                log("'mount -t tmpfs -o size=%sm -o mode=711 -o noexec none %s' failed errno %d '%s'\n" % (guest_home_dir_size, home_dir, processRet.returnCode, processRet.errOutput))
            return auth_return(pamh, -2)

        if not os.path.ismount(home_dir):
            if debugging:
                log("Mount error! Unable to ismount(%s)\n" % home_dir)
            return auth_return(pamh, 2, home_dir)

        if debugging:
            log("%s has been mounted as tmpfs\n" % home_dir)

        # only add guest username if not recycled
        recycledAccount = False;
        try:
            pwEntry = pwd.getpwnam(username)
            recycledAccount = True;

            if debugging:
                log("Recycled Guest Account current home '%s' should be '%s/home'\n" % (pwEntry.pw_dir, home_dir))

        except:
            processRet = runProcess(["useradd --system -m -d %s/home -g %s -s /bin/bash %s" % (home_dir, guest_group, username)])
            if processRet.returnCode != 0:
                if debugging:
                    log("'useradd --system -m -d %s/home -g %s %s' failed errno %d '%s'\n" % (home_dir, guest_group, username, processRet.returnCode, processRet.errOutput))
                return auth_return(pamh, -2)

        if recycledAccount == True:
            processRet = runProcess(["usermod -d %s/home %s" % (home_dir, username)])
            if processRet.returnCode != 0:
                if debugging:
                    log("'usermod -d %s/home %s' failed errnor %d '%s'\n" % (home_dir, username, processRet.returnCode, processRet.errOutput))
                return auth_return(pamh, -2)

            try:
                os.mkdir("%s/home" % (home_dir), 0700)
            except OSError as (errno, strerror):
                if debugging:
                    log("mkdir(%s/home, 0700) failed %d '%s'\n" % (home_dir, errno, strerror))
                return auth_return(pamh, -2)

            processRet = runProcess(["cp -rT /etc/skel %s/home" % (home_dir)])
            if processRet.returnCode != 0:
                if debugging:
                    log("'cp -rT /etc/skel %s/home' failed %d '%s'\n" % (home_dir, processRet.returnCode, processRet.errOutput))
                return auth_return(pamh, -2)

            try:
                os.chown("%s/home" % (home_dir), pwEntry.pw_uid, pwEntry.pw_gid)
            except OSError as (errno, strerror):
                if debugging:
                    log("chown(%s/home, %d, %d) failed %d '%s'\n" % (home_dir, pwEntry.pw_uid, pwEntry.pw_gid, processRet.returnCode, processRet.errOutput))
                return auth_return(pamh, -2)

            if debugging:
                log("Guest Account '%s' has been recycled properly\n" % (username))

        # deactivate lock screen
        processRet = runProcess(["su %s -p -c 'gconftool-2 --set --type bool /desktop/gnome/lockdown/disable_lock_screen True'" % (username)])
        if processRet.returnCode != 0 and debugging:
            log("'su %s -p -c 'gconftool-2 --set --type bool /desktop/gnome/lockdown/disable_lock_screen True'' failed errno %d '%s'\n" % (username, processRet.returnCode, processRet.errOutput))

        # make sure everything run smoothly before validating authentication
        try:
            pwd.getpwnam(username)
        except KeyError:
            if debugging:
                log("User %s not found! Unable to getpwnam(%s)\n" % (username, username))
            return auth_return(pamh, 3, home_dir)

        if debugging:
            log("%s has been created successfully\n" % username)

        return auth_return(pamh, 0)

    else:
        return auth_return(pamh, -1)



def pam_sm_setcred(pamh, flags, argv):
    """ Set Cred. """

    try:
        debugging = (len(argv) > 1 and argv[1] == 'debug')
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
    """ Open Session"""

    return auth_return(pamh, 0)




def pam_sm_close_session(pamh, flags, argv):
    """ Close Session, if user is guest
    destroy it but it seems quite dangerous"""

    try:
        debugging = (len(argv) > 1 and argv[1] == 'debug')
    except IndexError:
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
            log("Unable to read config file at /etc/security/guestlogin.conf, using default values.\n")

    if guest_enabled == 'false':
        return auth_return(pamh, 1)

    if pamh.get_user(None).find(guest_name) != -1:

        username = pamh.get_user(None)
        _home_dir = pwd.getpwnam(username).pw_dir
        home_dir = _home_dir[0:_home_dir.rfind('/')+1]

        # FIXME: should add a barrier to avoid infinite loop

        while True:

            processRet = runProcess(["ps h -u %s" % (username)])
            if processRet.returnCode != 0:
                if debugging:
                    log("'ps h -u %s' failed errno %d '%s'" % (username, processRet.returnCode, processRet.errOutput))
                break

            processList = processRet.stdOutput.split('\n')
            try:
                if len(processList) == 0:
                    break

                processRet = runProcess(["killall -9 -u %s" % (username)])
                if processRet.returnCode != 0 and debugging:
                    log("'killall -9 -u %s' failed errno %d '%s'" % (username, processRet.returnCode, processRet.errOutput))

            except IndexError:
                break

            # mmm it seems there is no msleep in python...
            # FIXME: to get ms resolution use select() like routine
            time.sleep(1)

        processRet = runProcess(["umount %s" % (home_dir)])
        if processRet.returnCode != 0 and debugging:
            log("'umount %s' failed errno %d '%s'" % (home_dir, processRet.returnCode, processRet.errOutput))

        processRet = runProcess(["umount -l %s" % (home_dir)])
        if processRet.returnCode != 0 and debugging:
            log("'umount -l %s' failed errno %d '%s'" % (home_dir, processRet.returnCode, processRet.errOutput))

        processRet = runProcess(["find /tmp -mindepth 1 -maxdepth 1 -uid %d" % (pwd.getpwnam(username).pw_uid)])
        if processRet.returnCode == 0:
            fileList = processRet.stdOutput.split('\n')
            try:
                for fileIndex in range(len(fileList)):
                    runProcess(["rm -rf %s" % (fileList[fileIndex])])
            except IndexError:
                pass

        processRet = runProcess(["userdel -f %s" % (username)])
        if processRet.returnCode != 0 and debugging:
            log("'userdel -f %s' failed errno %d '%s'" % (username, processRet.returnCode, processRet.errOutput))

        try:
            shutil.rmtree(home_dir)
        except OSError as (errno, strerror):
            if debugging:
                log("'shutil.rmtree(%s)' failed errno %d '%s'" % (home_dir, errno, strerror))

    return auth_return(pamh, 0)

