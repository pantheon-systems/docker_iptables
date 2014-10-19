import os
import json
import argparse
import unittest

from docker_iptables import *

import mock


class TestDockerIptables(unittest.TestCase):

    def setUp(self):
        self.chain = 'CHAIN'
        self.bridge = 'docker0'
        self.proto = 'tcp'
        self.host_ip = '0/0'
        self.host_port = 5001
        self.container_ip = ' 172.24.0.2'
        self.container_port = 5000

    def test_is_ipv4(self):
        self.assertTrue(is_ipv4('0/0'))
        self.assertTrue(is_ipv4('10.0.0.1'))
        self.assertFalse(is_ipv4('2001:24:203:4f20::dead:beef'))

    def test_is_ipv6(self):
        self.assertTrue(is_ipv6('0/0'))
        self.assertTrue(is_ipv6('2001:24:203:4f20::dead:beef'))
        self.assertFalse(is_ipv6('10.0.0.1'))

    def test_create_ipv4_nat_rule(self):
        expected = '-A {chain} ! -i {bridge} -p {proto} -m {proto}' \
                   ' --dport {host_port} -j DNAT' \
                   ' --to-destination {container_ip}:{container_port}'.format(chain=self.chain,
                                                                              bridge=self.bridge,
                                                                              proto=self.proto,
                                                                              host_port=self.host_port,
                                                                              container_ip=self.container_ip,
                                                                              container_port=self.container_port)
        rule = create_ipv4_nat_rule(self.chain,
                                    self.bridge,
                                    self.proto,
                                    self.host_port,
                                    self.container_ip,
                                    self.container_port)
        self.assertEqual(expected, rule)

    def test_create_ipv4_filter_rule(self):
        expected = '-A FORWARD -d {container_ip} ! -i {bridge} -o {bridge}' \
           ' -p {proto} -m {proto} --dport {container_port}'\
           ' -j ACCEPT\n'.format(container_ip=self.container_ip,
                                 bridge=self.bridge,
                                 proto=self.proto,
                                 container_port=self.container_port)
        rule = create_ipv4_filter_rule(self.container_ip,
                                       self.bridge,
                                       self.proto,
                                       self.container_port)
        self.assertEqual(expected, rule)

    def test_create_ipv6_nat_rule(self):
        expected = '-A {chain} ! -i {bridge} -p {proto} -m {proto}' \
                   ' --dport {host_port} -j DNAT' \
                   ' --to-destination [{container_ip}]:{container_port}'.format(chain=self.chain,
                                                                                bridge=self.bridge,
                                                                                proto=self.proto,
                                                                                host_port=self.host_port,
                                                                                container_ip=self.container_ip,
                                                                                container_port=self.container_port)
        rule = create_ipv6_nat_rule(self.chain,
                                    self.bridge,
                                    self.proto,
                                    self.host_port,
                                    self.container_ip,
                                    self.container_port)
        self.assertEqual(expected, rule)

    def test_create_ipv6_filter_rule(self):
        expected = '-A FORWARD -d {container_ip} ! -i {bridge} -o {bridge}' \
                   ' -p {proto} -m {proto} --dport {container_port}'\
                   ' -j ACCEPT\n'.format(container_ip=self.container_ip,
                                         bridge=self.bridge,
                                         proto=self.proto,
                                         container_port=self.container_port)
        rule = create_ipv6_filter_rule(self.container_ip,
                                       self.bridge,
                                       self.proto,
                                       self.container_port)
        self.assertEqual(expected, rule)

    @mock.patch('docker_iptables.docker_inspect')
    @mock.patch('subprocess.call')
    @mock.patch('os.path.exists')
    @mock.patch('os.remove')
    @mock.patch('__builtin__.open')
    def test_main(self, mock_open, mock_remove, mock_exists, mock_call, mock_inspect):
        args = argparse.Namespace()
        args.action = 'create'
        args.container_name = 'test-container'
        args.debug = True
        args.chain = self.chain
        args.ipv6 = True
        args.iptables_dir = '/tmp/iptables.d'
        args.ip6tables_dir = '/tmp/ip6tables.d'

        # we mock the (partial) json output of a call to exec `docker inspect`
        docker_inspect_hello_world = """
        {
           "NetworkSettings": {
                "Bridge": "docker0",
                "Gateway": "172.17.42.1",
                "IPAddress": "172.17.0.36",
                "IPPrefixLen": 16,
                "PortMapping": null,
                "Ports": {
                    "5001/tcp": [
                        {
                            "HostIp": "0.0.0.0",
                            "HostPort": "5000"
                        }
                    ]
                }
            }
        }
        """
        mock_inspect.return_value = json.loads(docker_inspect_hello_world)

        # run the app, check critical actions happened as we expected.
        main(args)

        # print mock_open
        # print mock_open.mock_calls

        # verify `docker inspect <container_name>` was executed
        mock_inspect.assert_called_once_with(args.container_name)

        # verify iptables and ip6tables were created with proper paths
        mock_open.assert_any_call(os.path.join(args.iptables_dir, '11-docker-container_' + args.container_name), 'w')
        mock_open.assert_any_call(os.path.join(args.ip6tables_dir, '11-docker-container_' + args.container_name), 'w')
        # we could also test the contents were written as expected by checking each write call, but
        # it is probably sufficient to only test the functions that create the rule strings.

        # verify iptables services were restarted
        mock_call.assert_any_call('systemctl restart iptables.service', shell=True)
        mock_call.assert_any_call('systemctl restart ip6tables.service', shell=True)


if __name__ == '__main__':
    unittest.main()
