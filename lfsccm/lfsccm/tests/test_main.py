import unittest
import mock
from lfsccm import main
import lfsccm


def mock_parallel_do_action(nodes, action):
    results = {}
    for node in nodes:
        results[node] = lfsccm.main.wrapper_action(node, action)
    return results

@mock.patch("lfsccm.main.parallel_do_action", side_effect=mock_parallel_do_action)
class TestMain(unittest.TestCase):

    def mock_io(self, body: str="", status: int=0):
        mock_io = mock.MagicMock()
        mock_io.read = lambda: body.encode("utf8")
        mock_io.channel.recv_exit_status.return_value = 0
        return mock_io


    def test_main_no_action(self, mock_action):
        self.assertEqual(-1, main.main())

    @mock.patch("sys.argv", ["lfsccm", "check-files"])
    @mock.patch("paramiko.client.SSHClient")
    def test_check_files(self, mock_cli, mock_action):
        self.assertEqual(0, main.main())

    @mock.patch("sys.argv", ["lfsccm", "check-ro-available"])
    @mock.patch("paramiko.client.SSHClient.connect")
    @mock.patch("paramiko.client.SSHClient.exec_command")
    def test_check_ro_available(self, mock_exec, mock_connect, mock_action):
        mock_exec.return_value = [
            None, self.mock_io("Lustre version: 2.16.0"), self.mock_io()]
        self.assertEqual(0, main.main())

    @mock.patch("sys.argv", ["lfsccm", "check-ro-available"])
    @mock.patch("paramiko.client.SSHClient.connect")
    @mock.patch("paramiko.client.SSHClient.exec_command")
    def test_check_ro_available_not_supported(
            self, mock_exec, mock_connect, mock_action):
        # lustre 2.14 doesn't support RO mode of PCC
        mock_exec.return_value = [
            None, self.mock_io("Lustre version: 2.14.0"), self.mock_io()]
        self.assertEqual(1, main.main())
