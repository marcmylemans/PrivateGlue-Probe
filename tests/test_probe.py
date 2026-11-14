import ipaddress
import socket
import unittest
from collections import namedtuple
from unittest import mock

import requests

import probe

Addr = namedtuple("Addr", "family address netmask")


def v4(address, netmask):
    return Addr(socket.AF_INET, address, netmask)


class NetworkSelectionTests(unittest.TestCase):
    def test_parse_subnet_accepts_cidr_and_the_old_short_form(self):
        self.assertEqual(ipaddress.ip_network("192.168.1.0/24"), probe.parse_subnet("192.168.1"))
        self.assertEqual(ipaddress.ip_network("10.0.0.0/23"), probe.parse_subnet("10.0.1.7/23"))
        self.assertEqual(ipaddress.ip_network("172.16.5.0/28"), probe.parse_subnet(" 172.16.5.0/28 "))

    def test_parse_subnet_rejects_nonsense_and_ipv6(self):
        for bad in ("", "banana", "300.1.1.0/24", "192.168.1.0/40", "fd00::/64"):
            with self.assertRaises(probe.ProbeError, msg=bad):
                probe.parse_subnet(bad)

    def test_only_private_networks_are_picked_automatically(self):
        interfaces = {
            "lan": [v4("192.168.10.25", "255.255.255.0"), Addr(socket.AF_INET6, "fe80::1", None)],
            "big": [v4("10.4.2.9", "255.255.254.0")],
            "loopback": [v4("127.0.0.1", "255.0.0.0")],
            "apipa": [v4("169.254.3.4", "255.255.0.0")],
            "wan": [v4("8.8.4.4", "255.255.255.0")],
            "vpn-cgnat": [v4("100.64.0.7", "255.192.0.0")],
            "documentation-range": [v4("192.0.2.10", "255.255.255.0")],
            "docker": [v4("172.17.0.1", "255.255.0.0")],
            "broken": [v4("10.0.0.1", None), v4("", "255.255.255.0"), v4("10.0.0.1", "banana")],
            "same-lan-again": [v4("192.168.10.26", "255.255.255.0")],
        }
        self.assertEqual(
            [ipaddress.ip_network("10.4.2.0/23"), ipaddress.ip_network("172.17.0.0/16"),
             ipaddress.ip_network("192.168.10.0/24")],
            probe.local_networks(interfaces),
        )

    def test_real_netmask_is_used_not_an_assumed_slash_24(self):
        nets = probe.local_networks({"x": [v4("10.20.30.200", "255.255.255.128")]})
        self.assertEqual([ipaddress.ip_network("10.20.30.128/25")], nets)

    def test_large_networks_are_refused_unless_the_limit_is_raised(self):
        probe.check_size(ipaddress.ip_network("192.168.0.0/22"), 1024)
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.check_size(ipaddress.ip_network("10.0.0.0/16"), 1024)
        self.assertIn("--max-hosts", str(ctx.exception))
        probe.check_size(ipaddress.ip_network("10.0.0.0/16"), 70000)


class ScanTests(unittest.TestCase):
    def test_ping_command_per_operating_system(self):
        self.assertEqual(["ping", "-n", "1", "-w", "1000", "10.0.0.1"], probe.ping_command("10.0.0.1", "Windows"))
        self.assertEqual(["ping", "-c", "1", "-W", "1", "10.0.0.1"], probe.ping_command("10.0.0.1", "Linux"))
        self.assertEqual(["ping", "-c", "1", "-t", "1", "10.0.0.1"], probe.ping_command("10.0.0.1", "Darwin"))

    def test_windows_unreachable_reply_is_not_a_device(self):
        done = mock.Mock(returncode=0, stdout=b"Reply from 192.168.1.1: Destination host unreachable.")
        with mock.patch("probe.subprocess.run", return_value=done):
            self.assertFalse(probe.ping_host("192.168.1.77"))
        done = mock.Mock(returncode=0, stdout=b"Reply from 192.168.1.77: bytes=32 time<1ms TTL=64")
        with mock.patch("probe.subprocess.run", return_value=done):
            self.assertTrue(probe.ping_host("192.168.1.77"))

    def test_ping_that_cannot_run_counts_as_no_answer(self):
        with mock.patch("probe.subprocess.run", side_effect=FileNotFoundError):
            self.assertFalse(probe.ping_host("10.0.0.1"))

    def test_normalize_mac(self):
        self.assertEqual("00:1a:2b:3c:4d:5e", probe.normalize_mac("00-1A-2B-3C-4D-5E"))
        self.assertEqual("00:0a:0b:0c:0d:0e", probe.normalize_mac("0:a:b:c:d:e"))   # macOS drops zeros
        for bad in ("", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "aa:bb:cc", "zz:bb:cc:dd:ee:ff"):
            self.assertEqual("", probe.normalize_mac(bad), bad)

    def test_parse_neighbors_windows(self):
        text = """
Interface: 192.168.1.20 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           3c-52-82-aa-bb-01     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
        table = probe.parse_neighbors(text)
        self.assertEqual("3c:52:82:aa:bb:01", table["192.168.1.1"])
        self.assertNotIn("192.168.1.255", table)

    def test_parse_neighbors_linux_and_macos(self):
        linux = ("192.168.1.1 dev eth0 lladdr 3c:52:82:aa:bb:01 REACHABLE\n"
                 "192.168.1.9 dev eth0  FAILED\n"
                 "fe80::1 dev eth0 lladdr 3c:52:82:aa:bb:01 router STALE\n")
        self.assertEqual({"192.168.1.1": "3c:52:82:aa:bb:01"}, probe.parse_neighbors(linux))
        mac = ("? (192.168.1.5) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]\n"
               "? (192.168.1.6) at (incomplete) on en0 ifscope [ethernet]\n")
        self.assertEqual({"192.168.1.5": "a4:83:e7:01:02:03"}, probe.parse_neighbors(mac))

    def test_scan_network_reports_only_answering_hosts_with_name_and_mac(self):
        alive = {"192.168.5.1", "192.168.5.6"}
        devices = probe.scan_network(
            ipaddress.ip_network("192.168.5.0/29"), workers=4,
            ping=lambda ip: ip in alive,
            hostname=lambda ip: "router.lan" if ip.endswith(".1") else "",
            neighbors=lambda: {"192.168.5.1": "aa:bb:cc:dd:ee:01", "192.168.5.99": "aa:bb:cc:dd:ee:99"},
        )
        self.assertEqual([
            {"ip_address": "192.168.5.1", "hostname": "router.lan", "mac_address": "aa:bb:cc:dd:ee:01"},
            {"ip_address": "192.168.5.6", "hostname": "", "mac_address": ""},
        ], devices)

    def test_scan_does_not_read_the_neighbour_table_when_nothing_answered(self):
        neighbors = mock.Mock(return_value={})
        self.assertEqual([], probe.scan_network(ipaddress.ip_network("192.168.5.0/30"), ping=lambda ip: False,
                                                neighbors=neighbors))
        neighbors.assert_not_called()


class SendTests(unittest.TestCase):
    KEY = "s3cret-key-value"

    def _response(self, status, body=None, bad_json=False):
        response = mock.Mock(status_code=status)
        response.json.side_effect = ValueError("no json") if bad_json else None
        response.json.return_value = body
        return response

    def test_server_url_accepts_base_or_full_address(self):
        full = "https://glue.example.com/api/discovered-devices"
        self.assertEqual(full, probe.server_url("https://glue.example.com"))
        self.assertEqual(full, probe.server_url("https://glue.example.com/"))
        self.assertEqual(full, probe.server_url(full))
        self.assertEqual("http://10.0.0.5:5000/api/discovered-devices", probe.server_url("http://10.0.0.5:5000"))
        for bad in ("", "glue.example.com", "ftp://x", "https://"):
            with self.assertRaises(probe.ProbeError, msg=bad):
                probe.server_url(bad)

    def test_local_address_detection_for_the_http_warning(self):
        for local in ("http://localhost:5000/x", "http://127.0.0.1/x", "http://192.168.1.5:5000/x", "http://10.1.1.1/x"):
            self.assertTrue(probe.is_local_address(local), local)
        for public in ("http://glue.example.com/x", "http://8.8.8.8/x"):
            self.assertFalse(probe.is_local_address(public), public)

    def test_send_posts_key_in_header_with_timeout_and_returns_count(self):
        post = mock.Mock(return_value=self._response(200, {"status": "ok", "count": 2}))
        devices = [{"ip_address": "10.0.0.1"}, {"ip_address": "10.0.0.2"}]
        self.assertEqual(2, probe.send("https://x/api/discovered-devices", self.KEY, devices, post=post))
        _, kwargs = post.call_args
        self.assertEqual({"X-API-KEY": self.KEY}, kwargs["headers"])
        self.assertEqual({"devices": devices}, kwargs["json"])
        self.assertEqual(30, kwargs["timeout"])
        self.assertTrue(kwargs["verify"])

    def test_http_errors_become_readable_messages_without_the_key(self):
        cases = {401: "API key", 404: "does not exist", 413: "too long", 429: "rate limiting", 500: "HTTP 500"}
        for status, expected in cases.items():
            post = mock.Mock(return_value=self._response(status, {"error": "x"}))
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.send("https://x/api/discovered-devices", self.KEY, [], post=post)
            self.assertIn(expected, str(ctx.exception))
            self.assertNotIn(self.KEY, str(ctx.exception))

    def test_non_json_answer_is_explained_instead_of_crashing(self):
        post = mock.Mock(return_value=self._response(200, bad_json=True))
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.send("https://x/api/discovered-devices", self.KEY, [], post=post)
        self.assertIn("did not answer like PrivateGlue", str(ctx.exception))

    def test_network_failures_become_readable_messages(self):
        for exc, expected in ((requests.exceptions.SSLError(), "certificate"),
                              (requests.exceptions.ConnectionError(), "Could not connect"),
                              (requests.exceptions.Timeout(), "30 seconds")):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.send("https://x/api/discovered-devices", self.KEY, [], post=mock.Mock(side_effect=exc))
            self.assertIn(expected, str(ctx.exception))


class CommandLineTests(unittest.TestCase):
    def _run(self, argv, env=None, scan=None):
        lines = []
        scan = scan or (lambda network, workers=0: [{"ip_address": "192.168.9.1", "hostname": "gw", "mac_address": ""}])
        with mock.patch.dict("os.environ", env or {}, clear=True), \
                mock.patch("probe.scan_network", side_effect=scan), \
                mock.patch("probe.send", return_value=1) as send:
            code = probe.run(argv, out=lines.append)
        return code, lines, send

    def test_dry_run_scans_but_sends_nothing_and_needs_no_key(self):
        code, lines, send = self._run(["--dry-run", "--subnet", "192.168.9.0/29"])
        self.assertEqual(0, code)
        send.assert_not_called()
        self.assertTrue(any("192.168.9.1" in line for line in lines))

    def test_key_and_server_come_from_the_environment(self):
        env = {"PRIVATEGLUE_API_KEY": "from-env", "PRIVATEGLUE_URL": "https://glue.example.com"}
        code, _, send = self._run(["--subnet", "192.168.9.0/29"], env=env)
        self.assertEqual(0, code)
        self.assertEqual(("https://glue.example.com/api/discovered-devices", "from-env"), send.call_args[0][:2])

    def test_old_backend_option_still_works(self):
        _, _, send = self._run(["--backend", "http://10.0.0.5:5000/api/discovered-devices", "--apikey", "k",
                                "--subnet", "192.168.9"])
        self.assertEqual("http://10.0.0.5:5000/api/discovered-devices", send.call_args[0][0])

    def test_missing_key_or_server_stops_before_scanning(self):
        scan = mock.Mock()
        for argv, env in ((["--server", "https://x.example"], {}), ([], {"PRIVATEGLUE_API_KEY": "k"})):
            with self.assertRaises(probe.ProbeError):
                self._run(argv + ["--subnet", "192.168.9.0/29"], env=env, scan=scan)
        scan.assert_not_called()

    def test_plain_http_to_a_public_server_warns(self):
        _, lines, _ = self._run(["--server", "http://glue.example.com", "--apikey", "k", "--subnet", "192.168.9.0/29"])
        self.assertTrue(any("plain http" in line for line in lines))
        _, lines, _ = self._run(["--server", "http://192.168.1.5:5000", "--apikey", "k", "--subnet", "192.168.9.0/29"])
        self.assertFalse(any("plain http" in line for line in lines))

    def test_same_address_in_two_networks_is_sent_once(self):
        _, _, send = self._run(["--server", "https://x.example", "--apikey", "k",
                                "--subnet", "192.168.9.0/29", "--subnet", "192.168.9.0/28"])
        self.assertEqual(1, len(send.call_args[0][2]))

    def test_oversized_auto_detected_network_is_skipped_not_fatal(self):
        nets = [ipaddress.ip_network("172.17.0.0/16"), ipaddress.ip_network("192.168.9.0/29")]
        with mock.patch("probe.local_networks", return_value=nets):
            code, lines, _ = self._run(["--dry-run"])
        self.assertEqual(0, code)
        self.assertTrue(any("Skipping 172.17.0.0/16" in line for line in lines))
        self.assertTrue(any("Scanning 192.168.9.0/29" in line for line in lines))
        with mock.patch("probe.local_networks", return_value=nets[:1]):
            with self.assertRaises(probe.ProbeError):
                self._run(["--dry-run"])

    def test_main_prints_errors_without_a_traceback(self):
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("sys.stderr") as err:
            self.assertEqual(1, probe.main(["--subnet", "banana", "--dry-run"]))
        self.assertIn("Error:", "".join(call.args[0] for call in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
