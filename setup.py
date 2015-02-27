from setuptools import setup

setup(
    name='docker_iptables',
    scripts=['docker_iptables.py'],
    version='0.0.3',
    tests_require=['pylint', 'mock'],
    test_suite="tests",
)
