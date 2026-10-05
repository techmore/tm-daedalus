import unittest
from unittest.mock import patch
from subprocess import CompletedProcess, TimeoutExpired
from daedalus.agent import discover_connected_networks
from daedalus.server import AgentHeartbeatRequest

class ConnectedNetworkTests(unittest.TestCase):
    def test_mac_actual_netmask(self):
        results = [CompletedProcess([], 0, "interface: en15\n"), CompletedProcess([], 0, "inet 10.20.0.111 netmask 0xffffff00 broadcast 10.20.0.255")]
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch("daedalus.agent.subprocess.run", side_effect=results):
            self.assertEqual(discover_connected_networks(), ["10.20.0.0/24"])

    def test_tunnel_is_not_lan(self):
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch("daedalus.agent.subprocess.run", return_value=CompletedProcess([], 0, "interface: utun4\n")) as run:
            self.assertEqual(discover_connected_networks(), [])
            self.assertEqual(run.call_count, 1)

    def test_linux_prefix_and_metric(self):
        outputs = ['[{"dev":"eth1","metric":100},{"dev":"eth0","metric":10}]', '[{"addr_info":[{"family":"inet","scope":"global","local":"192.168.4.12","prefixlen":23}]}]']
        with patch("daedalus.agent.platform.system", return_value="Linux"), patch("daedalus.agent.shutil.which", return_value="/usr/sbin/ip"), patch("daedalus.agent.subprocess.run", side_effect=[CompletedProcess([], 0, value) for value in outputs]) as run:
            self.assertEqual(discover_connected_networks(), ["192.168.4.0/23"])
            self.assertEqual(run.call_args.args[0][-1], "eth0")

    def test_timeout_and_old_client(self):
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch("daedalus.agent.subprocess.run", side_effect=TimeoutExpired("route", 3)):
            self.assertEqual(discover_connected_networks(), [])
        self.assertIsNone(AgentHeartbeatRequest().detected_networks)
        self.assertEqual(AgentHeartbeatRequest(detected_networks=["10.20.0.1/24"]).detected_networks, ["10.20.0.0/24"])
