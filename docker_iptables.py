#!/usr/bin/env python
#
#pylint: disable=line-too-long,invalid-name,missing-docstring,redefined-outer-name,too-many-arguments,too-many-locals,too-many-statements
#
#


DEBUG = True

import os
import sys
import time
import json
import subprocess

import logging as log


def setup_logging(loglevel=log.INFO):
    """initialize logging.
    Currently only logging to stdout and not directly to the journal to avoid double-logging
    since this script is intended to run from an ExecStartPost= of a systemd unit, its stdout
    will already be aggregated with that unit's journal logs, and it makes sense to combine this
    script's logs with the container unit's logs rather than making them separate.

    This uses the standard python logger instead of titan.pantheon.twistedLog for future
    portability and because we are not logging to the journal directly.
    """
    log.basicConfig(level=loglevel, format='%(levelname)-8s: %(message)s')


def is_ipv4(addr):
    """return true if addr looks like an ipv4 address, false otherwise"""
    if addr == '0/0' or '.' in addr:
        return True
    else:
        return False

def is_ipv6(addr):
    """return true if addr looks like an ipv6 address, false otherwise"""
    if addr == '0/0' or ':' in addr:
        return True
    else:
        return False


def docker_inspect(container_name, max_attempts=20):
    """Runs `docker inspect <container_name>` and parses its json output, returning a python dict.

    raises subprocess.CalledProcessError on non-zero exit status from docker
    """
    attempts = 0
    success = False
    while attempts < max_attempts and not success:
        try:
            result = subprocess.check_output('docker inspect {}'.format(container_name),
                                             stderr=subprocess.STDOUT,
                                             shell=True)
            success = True
        except subprocess.CalledProcessError:
            time.sleep(0.1)  # 100ms!!

        attempts += 1

    if success:
        return json.loads(result)[0]
    else:
        raise RuntimeError('Retries exhausted waiting for {} to become available'.format(container_name))


def create_ipv4_nat_rule(chain, bridge, proto, host_port, container_ip, container_port):
    """return a iptables v4 nat rule for forwarding a host port to a container IP:port"""
    return '-A {chain} ! -i {bridge} -p {proto} -m {proto}' \
           ' --dport {host_port} -j DNAT' \
           ' --to-destination {container_ip}:{container_port}'.format(chain=chain,
                                                                      bridge=bridge,
                                                                      proto=proto,
                                                                      host_port=host_port,
                                                                      container_ip=container_ip,
                                                                      container_port=container_port)

def create_ipv4_filter_rule(container_ip, bridge, proto, container_port):
    """return a iptables v4 filter rule for forwarding a host port to a container IP:port"""
    return '-A FORWARD -d {container_ip} ! -i {bridge} -o {bridge}' \
           ' -p {proto} -m {proto} --dport {container_port}'\
           ' -j ACCEPT\n'.format(container_ip=container_ip,
                                 bridge=bridge,
                                 proto=proto,
                                 container_port=container_port)


def create_ipv6_nat_rule(chain, bridge, proto, host_port, container_ip, container_port):
    """return a iptables v6 nat rule for forwarding a host port to a container IP:port"""
    return '-A {chain} ! -i {bridge} -p {proto} -m {proto}' \
           ' --dport {host_port} -j DNAT' \
           ' --to-destination [{container_ip}]:{container_port}'.format(chain=chain,
                                                                        bridge=bridge,
                                                                        proto=proto,
                                                                        host_port=host_port,
                                                                        container_ip=container_ip,
                                                                        container_port=container_port)

def create_ipv6_filter_rule(container_ip, bridge, proto, container_port):
    """return a iptables v4 filter rule for forwarding a host port to a container IP:port"""
    return '-A FORWARD -d {container_ip} ! -i {bridge} -o {bridge}' \
           ' -p {proto} -m {proto} --dport {container_port}'\
           ' -j ACCEPT\n'.format(container_ip=container_ip,
                                 bridge=bridge,
                                 proto=proto,
                                 container_port=container_port)


def write_iptables_file(filename, nat_rules, filter_rules):
    with open(filename, 'w') as f:
        f.write('*nat\n')
        for rule in nat_rules:
            f.write(rule + '\n')
        f.write('COMMIT\n')

        f.write('*filter\n')
        for rule in filter_rules:
            f.write(rule + '\n')
        f.write('COMMIT\n')


def remove_iptables_file(filename):
    if os.path.exists(filename):
        os.remove(filename)


def restart_iptables():
    subprocess.call('systemctl restart iptables.service', shell=True)


def restart_ip6tables():
    subprocess.call('systemctl restart ip6tables.service', shell=True)


def main(args):
    """args should be a Namespace() with following attributes:

        - action (string):         "create" or "delete"
        - container_name (string): name of a docker container
        - debug (bool):            enable debug logging
        - chain (string):          iptables name to attach docker container rules onto
        - ipv6 (bool):             enable generating ip6tables (ipv6) rules in addition to ipv4
        - iptables_dir (string):   directory containing iptables rules files
        - ip6tables_dir (string):  directory containing ip6tables rules files
    """

    loglevel = log.DEBUG if args.debug else log.INFO
    setup_logging(loglevel)

    log.debug(args)

    container = args.container_name
    chain = args.chain
    enable_ipv6 = args.ipv6
    iptables_file = os.path.join(args.iptables_dir, '11-docker-container_' + container)
    ip6tables_file = os.path.join(args.ip6tables_dir, '11-docker-container_' + container)

    if args.action == 'create':
        nat4_rules = []
        filter4_rules = []
        nat6_rules = []
        filter6_rules = []

        try:
            container_data = docker_inspect(container)
        except subprocess.CalledProcessError as e:
            log.error('Error retrieving container data, container: {}": {}'.format(container, e))
            sys.exit(1)

        network = container_data['NetworkSettings']
        container_ip = network['IPAddress']
        bridge = network['Bridge']
        mappings = network['Ports']

        if len(mappings) == 0:
            log.info('container {} does not have any port mappings, nothing to do.'.format(container))
            sys.exit(0)

        for (container_map, host_map) in mappings.iteritems():
            # `container_map` example: (String): "5000/tcp"
            # `host_map`      example: list of single dict: [{u'HostPort': u'5001', u'HostIp': u'0.0.0.0'}]
            (container_port, proto) = container_map.split('/')
            host_ip = host_map[0]['HostIp']
            host_port = host_map[0]['HostPort']

            # convert 0.0.0.0 to 0/0 which is accepted by both iptables and ip6tables
            host_ip = '0/0' if host_ip == '0.0.0.0' else host_ip

            # iptables (ipv4) rules
            if is_ipv4(host_ip):
                nat4_rules.append(create_ipv4_nat_rule(chain, bridge, proto, host_port, container_ip, container_port))
                filter4_rules.append(create_ipv4_filter_rule(container_ip, bridge, proto, container_port))

            # ip6tables (ipv6) rules
            # NOTE: ipv6 nat'ing is a weird concept but linux supports it since 3.7+. At this time
            #        Docker (1.2) does not seem to support it well but we at least want to support
            #        the case of making our apps available on the host's ipv6 addr, so we try to make
            #        some rules to publish our services on ipv4 and ipv6.
            if enable_ipv6 and is_ipv6(host_ip):
                nat6_rules.append(create_ipv6_nat_rule(chain, bridge, proto, host_port, container_ip, container_port))
                filter6_rules.append(create_ipv6_filter_rule(container_ip, bridge, proto, container_port))

        log.debug('nat4_rules:\n{}\n'.format(nat4_rules))
        log.debug('filter4_rules:\n{}\n'.format(filter4_rules))
        log.debug('nat6_rules:\n{}\n'.format(nat6_rules))
        log.debug('filter6_rules:\n{}\n'.format(filter6_rules))

        log.info('Writing iptables rules to {} and initiating iptables reload'.format(iptables_file))
        write_iptables_file(iptables_file, nat4_rules, filter4_rules)
        restart_iptables()

        if enable_ipv6:
            log.info('Writing ipt6ables rules to {} and initiating iptables reload'.format(ip6tables_file))
            write_iptables_file(ip6tables_file, nat6_rules, filter6_rules)
            restart_ip6tables()

    if args.action == 'delete':
        log.info('Deleting iptables rule files: {}, {}'.format(iptables_file, ip6tables_file))
        remove_iptables_file(iptables_file)
        remove_iptables_file(ip6tables_file)

        log.info('reloading iptables rules')
        restart_iptables()

        if enable_ipv6:
            restart_ip6tables()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # required, positional args
    parser.add_argument('action', choices=['create', 'delete'])
    parser.add_argument('container_name', help='name of container')

    # optional, flag based args
    parser.add_argument('--iptables-dir', help='Directory to store iptables files', default='/etc/iptables.d')
    parser.add_argument('--ip6tables-dir', help='Directory to store ip6tables files', default='/etc/ip6tables.d')
    parser.add_argument('--chain', help='Name of docker iptables chain', default='DOCKER_CONTAINERS')
    parser.add_argument('--ipv6', help='Enable ip6tables. Experimental. Docker ipv6 support requires the lxc exec driver.', action='store_true')
    parser.add_argument('--debug', help='Enable debug logging.', action='store_true')
    args = parser.parse_args()

    main(args)

