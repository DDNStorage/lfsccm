#!/usr/bin/python3 -u

# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php


import glob
import logging
import os
import paramiko
import re
from distutils.version import LooseVersion
from itertools import zip_longest
from multiprocessing import Pool
import argparse


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


class BaseListArgAction(argparse.Action):
    my_type = None

    def __init__(self, option_strings, dest, **kwargs):
        if not self.my_type:
            raise NotImplementedError()
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string):
        values = [self.my_type(v) for v in values.split(",")]
        setattr(namespace, self.dest, values)


class StrListArgAction(BaseListArgAction):
    my_type = str


class IntListArgAction(BaseListArgAction):
    my_type = int


AVAILABLE_OPTIONS = {
    "nodes":
        {"kargs": ["-n", "--nodes"],
         "kwargs": {"type": str,
                    "default": "",
                    "action": StrListArgAction,
                    "required": True,
                    "help": "nodes for pcc - format: <node,>"}},
    "rwids":
        {"kargs": ["-w", "--rw-ids"],
         "kwargs": {"type": str,
                    "default": "",
                    "action": IntListArgAction,
                    "required": True,
                    "help": "rw ids for pcc - format: <id,>"}},
    "roids":
        {"kargs": ["-r", "--ro-ids"],
         "kwargs": {"type": str,
                    "default": "",
                    "action": IntListArgAction,
                    "required": True,
                    "help": "ro ids for pcc - format: <id,>"}},
    "files":
        {"kargs": ["-f", "--files"],
         "kwargs": {"type": str,
                    "default": "",
                    "action": StrListArgAction,
                    "required": True,
                    "help": "files to handle on pcc - format: <path,>"}},
}


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
                if not LooseVersion(version) > \
                        LooseVersion(MIN_LUSTRE_VERSION):
                    result['rc'] = 1
                    result['stderr'] = \
                        "PCC RO mode requires Lustre {} or higher, " \
                        "but detected version is {}".format(
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
        if not isinstance(self.rw_id, int):
            raise Exception("rw_id must be int: {}".format(self.rw_id))

    def _validate_ro_id(self):
        if not self.ro_id:
            raise Exception("Missing ro_id")
        if not isinstance(self.ro_id, int):
            raise Exception("ro_id mubst be int: {}".format(self.ro_id))

    def _validate_pcc_files(self):
        if not self.pcc_files:
            raise Exception("Missing pcc_files")
        self.pcc_files.validate()

    def _run_ssh(self, commands, login_user='root', timeout=TIMEOUT):
        results = []
        client = paramiko.client.SSHClient()
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
                filepath = re.sub('\\*+', '**', filepath)

            target_files = []
            for expand_file in filepath.split(','):  # expand_file=[path]
                if '*' in expand_file:
                    target_files.extend(
                        glob.glob(expand_file, recursive=is_recursive))
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


def wrapper_action(node, action):
    try:
        func = node.__getattribute__(action)
    except AttributeError:
        # FIXME: this logger is used before assignment
        # logger.error("Not [%s] function of %s", action, node.__class__)
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


def main() -> int:
    logger = setup_logger(__name__)

    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(
        dest="actions",
        help="Action verb for operation")
    attach_parser = sub_parser.add_parser("attach")
    # attach
    for option in ["nodes", "roids", "rwids", "files"]:
        attach_parser.add_argument(
            *AVAILABLE_OPTIONS[option]["kargs"],
            **AVAILABLE_OPTIONS[option]["kwargs"])
    # detach
    detach_parser = sub_parser.add_parser("detach")
    for option in ["nodes", "roids", "rwids", "files"]:
        detach_parser.add_argument(
            *AVAILABLE_OPTIONS[option]["kargs"],
            **AVAILABLE_OPTIONS[option]["kwargs"])
    # check-ssh-connection
    ssh_parser = sub_parser.add_parser("check-ssh-connection")
    ssh_options = AVAILABLE_OPTIONS["nodes"].copy()
    ssh_options["kwargs"]["required"] = False
    ssh_parser.add_argument(
        *ssh_options["kargs"], **ssh_options["kwargs"])

    # check-fies
    files_parser = sub_parser.add_parser("check-files")
    files_options = AVAILABLE_OPTIONS["files"].copy()
    files_options["kwargs"]["required"] = False
    files_parser.add_argument(
        *files_options["kargs"],
        **files_options["kwargs"])

    # check-ro-available
    sub_parser.add_parser("check-ro-available")

    try:
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        return -1

    # check action
    if not args.actions:
        logger.error("Please input action")
        parser.print_help()
        return -1

    action = args.actions
    # FIXME: for safety set empty list if it's not required
    nodes = []
    ro_ids = []
    rw_ids = []
    files = []
    if hasattr(args, "nodes"):
        nodes = args.nodes
    if hasattr(args, "ro_ids"):
        ro_ids = args.ro_ids
    if hasattr(args, "rw_ids"):
        rw_ids = args.rw_ids
    if hasattr(args, "files"):
        files = args.files

    # Set default
    if action in VALIED_CHK_ACTIONS:
        if not nodes:
            # FIXME: this is used on both check-ro-available and check-files
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
            return -1

    # Run actions
    if action in VALIED_ACTIONS:
        ret = parallel_do_action(pccs, action)
        for node, async_result in ret.items():
            for result in async_result.get():
                if result['stderr']:
                    logger.warning("{}: {}\n{}".format(
                        node.hostname, result['arg'], result['stderr']))

    # Run check actions
    elif action in VALIED_CHK_ACTIONS:
        action = action.replace('-', '_')
        ret = parallel_do_action(pccs, action)
        check = True
        for node, async_result in ret.items():
            for result in async_result.get():
                if result['rc'] == 0:
                    continue
                else:
                    check = False
                    logger.warning("{}: {}\n{}".format(
                        node.hostname, result['arg'], result['stderr']))
        if not check:
            return 1

    return 0


if __name__ == "__main__":
    main()
