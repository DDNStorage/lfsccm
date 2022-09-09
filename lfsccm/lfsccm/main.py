# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

#!/usr/bin/python3 -u

import getopt
import glob
import logging
import os
import paramiko
import re
import sys
from distutils.version import LooseVersion
from itertools import zip_longest
from multiprocessing import Pool

# Global
SSH_USER = 'root'  # os.getlogin()
LOG_LEVEL = logging.DEBUG
TIMEOUT = 600  # seconds
MIN_LUSTRE_VERSION = "2.16"  # PCC RO mode requires 2.16 or higher
VALIED_ACTIONS = [
    "attach",
    "detach",
]
VALIED_CHK_ACTIONS = [
    "check-ssh-connection",
    "check-files",
    "check-ro-available"
]


class Pcc(object):
    def __init__(self, hostname, rw_id=None, ro_id=None, pcc_files=None):
        self.hostname = hostname
        self.rw_id = rw_id
        self.ro_id = ro_id
        self.pcc_files = pcc_files

    def attach(self):
        commands = []
        if self.pcc_files.rw_files:
            quoted_files = [self._quote(x) for x in self.pcc_files.rw_files]
            commands.append(
                "lfs pcc attach -i {id} {pcc_files}".format(
                    id=self.rw_id,
                    pcc_files=" ".join(quoted_files)
                )
            )
        if self.pcc_files.ro_files:
            quoted_files = [self._quote(x) for x in self.pcc_files.ro_files]
            commands.append(
                "lfs pcc attach -r -i {id} {pcc_files}".format(
                    id=self.ro_id,
                    pcc_files=" ".join(quoted_files)
                )
            )
        return self._run_ssh(commands, SSH_USER)

    def detach(self):
        commands = []
        all_files = self.pcc_files.get_all_files()
        quoted_files = [self._quote(x) for x in all_files]
        if quoted_files:
            commands.append(
                "lfs pcc detach {pcc_files}".format(
                    pcc_files=" ".join(quoted_files)
                )
            )
        return self._run_ssh(commands, SSH_USER)

    def check_ssh_connection(self):
        commands = []
        commands.append("exit")
        return self._run_ssh(commands, SSH_USER)

    def check_files(self):
        commands = []
        all_files = self.pcc_files.get_all_files()
        quoted_files = [self._quote(x) for x in all_files]
        if quoted_files:
            commands.append(
                "lfs path2fid {pcc_files}".format(
                    pcc_files=" ".join(quoted_files)
                )
            )
        return self._run_ssh(commands, SSH_USER)

    def check_ro_available(self):
        commands = []
        commands.append("lctl lustre_build_version")
        results = self._run_ssh(commands, SSH_USER)
        for result in results:
            if result['rc'] != 0 or not result['stdout']:
                return results

            ver_m = re.match('Lustre version: (.*)', result['stdout'])
            if not ver_m or not ver_m.groups():
                return results

            for version in ver_m.groups():
                if not LooseVersion(version) > LooseVersion(MIN_LUSTRE_VERSION):
                    result['rc'] = 1
                    result['stderr'] = \
                        "PCC RO mode requires Lustre {} or higher, but detected version is {}".format(
                            MIN_LUSTRE_VERSION, version)
        return results

    def validate(self, action):
        if not isinstance(action, str):
            raise Exception("Invalied action [{}]".format(action))

        if action == "attach":
            required_options = ["hostname", "rw_id", "ro_id", "pcc_files"]
        elif action == "detach":
            required_options = ["hostname", "pcc_files"]
        elif action == "check-ssh-connection":
            required_options = ["hostname"]
        elif action == "check-files":
            required_options = ["hostname", "pcc_files"]
        elif action == "check-ro-available":
            required_options = []
        else:
            raise Exception("Invalied action [{}]".format(action))

        for opt in required_options:
            self.__getattribute__("_validate_" + opt)()

    def _validate_hostname(self):
        if not self.hostname:
            raise Exception("Missing hostname")
        if not isinstance(self.hostname, str):
            raise Exception("hostname is not str")

    def _validate_rw_id(self):
        if not self.rw_id:
            raise Exception("Missing rw_id")
        if not self.rw_id.isdecimal():
            raise Exception("rw_id is not decimal: {}".format(self.rw_id))

    def _validate_ro_id(self):
        if not self.ro_id:
            raise Exception("Missing ro_id")
        if not self.ro_id.isdecimal():
            raise Exception("ro_id is not decimal: {}".format(self.ro_id))

    def _validate_pcc_files(self):
        if not self.pcc_files:
            raise Exception("Missing pcc_files")
        self.pcc_files.validate()

    def _run_ssh(self, commands, login_user='root', timeout=TIMEOUT):
        results = []
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        client.connect(self.hostname, username=login_user, timeout=timeout)
        for cmd in commands:
            _, stdout, stderr = client.exec_command(cmd)

            results.append({
                "arg": cmd,
                "rc": stdout.channel.recv_exit_status(),
                "stdout": str(stdout.read(), 'utf-8'),
                "stderr": str(stderr.read(), 'utf-8'),
            })

        client.close()
        return results

    def _quote(self, s):
        # Modify shlex.quote to allow asterisks
        _find_unsafe = re.compile(r'[^\w^*@%+=:,./-]', re.ASCII).search

        if not s:
            return "''"
        if _find_unsafe(s):
            # use single quotes, and put single quotes into double quotes
            # the string $'b is then quoted as '$'"'"'b'
            # and allow asterisks
            s = "'" + s.replace("'", "'\"'\"'").replace("*", "'*'") + "'"

        return '"' + s + '"'


class PccFiles(object):
    def __init__(self, files, cache_rw):
        self.rw_files, self.ro_files = self._expand_files(files)
        if not cache_rw:
            self.rw_files = []

    def get_all_files(self):
        return self.rw_files + self.ro_files

    def validate(self):
        # Remove duplicates
        rw_set = set(self.rw_files)
        ro_set = set(self.ro_files)

        duplicates = rw_set & ro_set
        if duplicates:
            raise Exception('Duplicate files in --rw-files and --ro-files')

        self.rw_files = list(rw_set)
        self.ro_files = list(ro_set)

    def _expand_files(self, files):
        rw_files = []
        ro_files = []

        for tmp_files in files:  # files=[path,path:rw:r, path,path:ro:r]
            filepath, mode, recursive = tmp_files.split(':')
            # filepath=[path,path,・・・]
            # mode=rw
            # recursive=r

            is_recursive = False
            if recursive == 'r':
                is_recursive = True
                filepath = re.sub('\*+', '**', filepath)

            target_files = []
            for expand_file in filepath.split(','):  # expand_file=[path]
                if '*' in expand_file:
                    target_files.extend(glob.glob(expand_file, recursive=is_recursive))
                else:
                    target_files.append(expand_file)

            for target_file in target_files:
                if os.path.isdir(target_file):
                    continue
                if mode == 'rw':
                    rw_files.append(target_file)
                elif mode == 'ro':
                    ro_files.append(target_file)

        return rw_files, ro_files


def setup_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # console handler
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    ch_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] %(message)s",
        "%Y/%m/%d-%H:%M:%S")
    ch.setFormatter(ch_formatter)

    logger.addHandler(ch)
    return logger


def usage():
    print("Usage: pcc [options] [action]")
    print("actions:")
    print("  attach")
    print("    Required options: nodes, rw-ids, ro-ids, files")
    print("  detach")
    print("    Required options: nodes, files")
    print("  check-ssh-connection")
    print("    Required options: nodes")
    print("  check-files")
    print("    Required options: files")
    print("  check-ro-available")
    print("    Required options: nothing")
    print("options:")
    print("  -n / --nodes=<node,>")
    print("  -w / --rw-ids=<id,>")
    print("  -r / --ro-ids=<id,>")
    print("  -f / --files=<path,>")
    print("  -h / --help")


def wrapper_action(node, action):
    try:
        func = node.__getattribute__(action)
    except:
        logger.error("Not [%s] function of %s", action, node.__class__)
        return -1
    return func()


def parallel_do_action(nodes, action):
    workpool = Pool()
    results = {}
    for node in nodes:
        results[node] = workpool.apply_async(wrapper_action, (node, action))
    workpool.close()
    workpool.join()
    return results


def parse_arg(arg):
    if not arg:
        return []
    return arg.replace(' ', '').split(',')


def main():
    logger = setup_logger(__name__)

    options, args = getopt.getopt(
        sys.argv[1:],
        "n:w:r:f:h",
        ["nodes=",
         "rw-ids=",
         "ro-ids=",
         "files=",
         "help"]
    )

    # check options
    nodes, rw_ids, ro_ids, files = ([] for i in range(4))
    for opt, arg in options:
        if opt in ('-n', '--nodes'):
            nodes = parse_arg(arg)
        elif opt in ('-w', '--rw-ids'):
            rw_ids = parse_arg(arg)
        elif opt in ('-r', '--ro-ids'):
            ro_ids = parse_arg(arg)
        elif opt in ('-f', '--files'):
            files.append(arg)
        elif opt in ('-h', '--help'):
            usage()
            sys.exit(1)
        else:
            logger.error("Invalid option [{}]".format(opt))
            usage()
            sys.exit(1)

    # check action
    if not args:
        logger.error("Please input action")
        usage()
        sys.exit(-1)

    action = args[0].lower()

    # Set default
    if action in VALIED_CHK_ACTIONS:
        if not nodes:
            nodes = [os.uname()[1]]

    # Create Pcc instances
    pccs = []
    first_pcc = True
    for node, rw_id, ro_id in zip_longest(nodes, rw_ids, ro_ids):
        # In rw mode, only the first pcc caches the files.
        if first_pcc:
            pccs.append(Pcc(node, rw_id, ro_id, PccFiles(files, first_pcc)))
            first_pcc = False
        else:
            pccs.append(Pcc(node, rw_id, ro_id, PccFiles(files, first_pcc)))

    # Validate
    for pcc in pccs:
        try:
            pcc.validate(action)
        except Exception as e:
            logger.error("{}".format(str(e)))
            sys.exit(-1)

    # Run actions
    if action in VALIED_ACTIONS:
        ret = parallel_do_action(pccs, action)
        for node, results in ret.items():
            for result in results.get():
                if result['stderr']:
                    logger.warning("{}: {}\n{}".format(
                        node.hostname, result['arg'], result['stderr']))

    # Run check actions
    elif action in VALIED_CHK_ACTIONS:
        action = action.replace('-', '_')
        ret = parallel_do_action(pccs, action)
        check = True
        for node, results in ret.items():
            for result in results.get():
                if result['rc'] == 0:
                    continue
                else:
                    check = False
                    logger.warning("{}: {}\n{}".format(
                        node.hostname, result['arg'], result['stderr']))
        if not check:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()