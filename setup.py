from setuptools import setup

setup(
    name='docker_iptables',
    scripts=['docker_iptables.py'],
    version='0.0.1',
    tests_require=['mock'],
    test_suite="tests",
)