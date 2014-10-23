from setuptools import setup

setup(
    name='docker_iptables',
    scripts=['docker_iptables.py'],
    version='0.0.2',
    tests_require=['pylint', 'mock'],
    test_suite="tests",
)
