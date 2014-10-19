docker_iptables
===============

This script is intended to handle Docker iptables port-forwardings manually, for those times when
you can't let Docker manage iptables on its own because it conflicts with other things on the
system that are also trying to manage iptables.

Usage
-----

### Assumptions / Pre-reqs:

- `systemd` is your init and containers will be managed by systemd .service units.
- Canonical source for iptables rules is `/etc/iptables.d/` and `/etc/ip6tables.d/`
- A service named `iptables.service` exists and when stated or restarted will flush all running
  iptables rules and reload rulesfrom the .d directories.

### Using this script:

1. The docker daemon should be configured to start with `--iptables=false`.
2. Create an `/etc/iptables.d/10_docker` file with the following rules. These are the base rules that
   would normally get created when the docker daemon is started. NOTE: You must use a chain name other
   than DOCKER because even with `--iptables=false` docker will remove this chain on startup (bug in docker?).

        *nat
        :DOCKER_CONTAINERS - [0:0]
        -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER_CONTAINERS
        -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER_CONTAINERS
        -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
        COMMIT
        *filter
        -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
        -A FORWARD -i docker0 -o docker0 -j ACCEPT
        COMMIT

3. `ExecStartPost=` and `ExecStopPost=` commands in each docker container .service:

        [Unit]
        Description=hello-world docker service
        After=docker.service
        Requires=docker.service

        [Service]
        SyslogIdentifier=hello-world
        ExecStartPre=-/usr/bin/docker rm hello-world
        ExecStart=/usr/bin/docker run  --name="hello-world" --publish="5000:5000" --rm=true quay.io/getpantheon/hello-world:master
        ExecStartPost=/opt/titan/utilities/docker/docker-iptables.py create hello-world
        ExecStop=-/usr/bin/docker stop hello-world
        ExecStopPost=/opt/titan/utilities/docker/docker-iptables.py delete hello-world
        Restart=always
        RestartSec=10s
        TimeoutStartSec=120
        TimeoutStopSec=15

        [Install]
        WantedBy=multi-user.target

### Manual usage:

The script can also be run against any running container:

    docker-iptables.py create container-name
    docker-iptables.py delete container-name

The above commands will read the port mappings from `docker inspect` of the running container and
add or delete the rules from `/etc/iptables.d`. It will also call `systemctl restart iptables.service`
to load or remove the rules from the running config.

Testing
-------

1. run unit tests: `python setup.py test`
2. run pylint test: `pylint docker_iptables.py`

