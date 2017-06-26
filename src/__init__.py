#!/usr/bin/env python
'''
SSHv2 Proxy package module
'''

__version__ = '0.0.1'
__author__ = 'Tobias Diaz'
__email__ = 'tobias.deb@gmail.com'
__license__ = 'GPLv3'

__all__ = ['sshv2', '__main__']

try:
    # Python 3
    from sshv2.sshv2 import *
except ImportError:
    # Python 2
    from sshv2 import *
