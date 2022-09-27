import unittest
from unittest import mock
from lfsccm import main
import lfsccm


def mock_parallel_do_action(nodes, action):
    results = {}
    for node in nodes:
        # apply_async call generates AsyncResults. To emulate, wrap
        # the result with a mock equipes get() call
        mock_async_result = mock.MagicMock()
        actual_result = lfsccm.main.wrapper_action(node, action)
        # create iterator to respond only once
        getter = iter([actual_result])
        mock_async_result.get = lambda: next(getter)
        results[node] = mock_async_result
    return results


class BaseTestMain(unittest.TestCase):
    argv = None

    def setUp(self):
        self.patchers = [
            mock.patch("lfsccm.main.parallel_do_action",
                       side_effect=mock_parallel_do_action),
            mock.patch("sys.argv", self.argv.split()),
        ]
        for patch in self.patchers:
            patch.start()

    def tearDown(self):
        for patch in self.patchers:
            patch.stop()

    def mock_io(self, body: str="", status: int=0):
        mock_io = mock.MagicMock()
        mock_io.read = lambda: body.encode("utf8")
        mock_io.channel.recv_exit_status.return_value = 0
        return mock_io


class TestMain(BaseTestMain):
    argv = "lfsccm"

    def test_main_no_action(self):
        self.assertEqual(-1, main.main())


@mock.patch("paramiko.client.SSHClient.connect")
@mock.patch("paramiko.client.SSHClient.exec_command")
class TestMainCheckFiles(BaseTestMain):
    # FIXME: use something like optparse to add options in anywhare
    # in the args, and handle syntax errors to notify what was wrong
    # with in the errors.
    argv = "lfsccm --files=/sample/file:ro:0 check-files"

    @mock.patch("sys.argv", ["lfsccm", "check-files"])
    def test_check_files_no_files_specified(self, mock_exec, mock_connect):
        # FIXME: exit 1 because no requremet args found
        self.assertEqual(0, main.main())

    def test_check_files_with_args(self, mock_exec, mock_connect):
        mock_exec.return_value = [
            None, self.mock_io(), self.mock_io()]
        self.assertEqual(0, main.main())

    def test_check_files_not_exist(self, mock_exec, mock_connect):
        failed_io = self.mock_io("No such file or directory")
        failed_io.channel.recv_exit_status.return_value = 1
        mock_exec.return_value = [
            None, failed_io, self.mock_io()]
        self.assertEqual(1, main.main())


@mock.patch("paramiko.client.SSHClient.connect")
@mock.patch("paramiko.client.SSHClient.exec_command")
class TestMainROAvailable(BaseTestMain):
    argv = "lfsccm check-ro-available"

    def test_check_ro_available(self, mock_exec, mock_connect):
        mock_exec.return_value = [
            None, self.mock_io("Lustre version: 2.16.0"), self.mock_io()]
        self.assertEqual(0, main.main())

    def test_check_ro_available_not_supported(
            self, mock_exec, mock_connect):
        # lustre 2.14 doesn't support RO mode of PCC
        mock_exec.return_value = [
            None, self.mock_io("Lustre version: 2.14.0"), self.mock_io()]
        self.assertEqual(1, main.main())


@mock.patch("paramiko.client.SSHClient.connect")
@mock.patch("paramiko.client.SSHClient.exec_command")
class TestMainSSHConnection(BaseTestMain):
    argv = "lfsccm check-ssh-connection"

    def test_check_ssh_connection(self, mock_exec, mock_connect):
        mock_exec.return_value = [
            None, self.mock_io(), self.mock_io()]
        self.assertEqual(0, main.main())
        mock_exec.assert_called_with("exit")
