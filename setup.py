#!/usr/bin/env python
'''
SSHv2 Proxy setup module
'''

__version__ = '0.0.1'
__author__ = 'Tobias Diaz'
__email__ = 'tobias.deb@gmail.com'
__license__ = 'GPLv3'

from setuptools import setup
from codecs import open
from os import path

cwd = path.abspath(path.dirname(__file__))

with open(path.join(cwd, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='SSHv2 Proxy',
    version=__version__,
    description='Simple SSHv2 server proxy',
    long_description=long_description,
    url='https://github.com/int-0/ssh-proxy',
    author='Tobias Diaz',
    author_email='tobias.deb@gmail.com',
    license='GPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Networking',
        'License :: OSI Approved :: GPLv3 License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5'
    ],
    keywords='networking development',
    packages=['sshv2'],
    package_dir = {'sshv2': 'src'},
    install_requires=['paramiko'],
    entry_points={
        'console_scripts': [
            'ssh-proxy = sshv2.__main__:main'
        ]
    }
)
