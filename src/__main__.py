#!/usr/bin/env python
'''
SSHv2 Proxy
'''

__version__ = '0.0.1'
__author__ = 'Tobias Diaz'
__email__ = 'tobias.deb@gmail.com'
__license__ = 'GPLv3'

import os
import sys
import os.path
import logging
import argparse

import sshv2

# Some default settings and magic numbers

DEFAULT_SSH_PORT = 22
DEFAULT_LISTEN_ADDRESS = '0.0.0.0'
DEFAULT_LISTEN_PORT = 2200
DEFAULT_SERVER_KEY = '$HOME/.ssh/id_rsa'

OK = 0
ERR_BAD_CMDLINE = 1
ERR_NET_ERROR = 2
ERR_INVALID_KEY = 3
ERR_SERVER_ERROR = 4

# Logging
_INF = logging.info
_ERR = logging.error
_WRN = logging.warning


class TunnelConfig(object):
    '''
    Container of several proxy options
    '''
    def __init__(self, user_options):
        self._server_id = user_options.server_id or sshv2.detect_server_id(
            (user_options.SERVER, user_options.server_port))
        self._user = user_options.user_bypass
        self._packet_debug = user_options.packet_debug

    @property
    def server_id(self):
        '''Return server_id'''
        return self._server_id

    @property
    def user(self):
        '''Return user or None for not user-bypass'''
        return self._user

    @property
    def packet_debug(self):
        '''Return is packet trace is enabled'''
        return self._packet_debug


def main(args=None):
    '''Parse command line, make the proxy and wait for end'''
    user_options = parse_commandline()

    if user_options.debug:
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    logging.basicConfig(
        level=logging.DEBUG if user_options.debug else logging.INFO)

    proxy_endpoint = (user_options.listen_address, user_options.listen_port)
    tunnel_config = TunnelConfig(user_options)
    server_endpoint = (user_options.SERVER, user_options.server_port)
    server_key = load_key(user_options.private_key)
    if server_key is None:
        sys.exit(ERR_INVALID_KEY)
    try:
        _INF('Waiting incomming connections on %s:%s...' % proxy_endpoint)
        sshv2.SimpleSocketServer(proxy_endpoint,
                                 server_endpoint, server_key,
                                 tunnel_config).serve_forever()
    except sshv2.ProxyError as error:
        sys.exit(ERR_SERVER_ERROR)
    sys.exit(OK)


def parse_commandline():
    '''Parse and check command line'''
    parser = argparse.ArgumentParser(description='Make a SSHv2 server proxy.')

    parser.add_argument('SERVER', help='Server to forward connections to')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--debug',
                        action='store_true', default=False,
                        help='Be verbose (PRIVATE CONTENT CAN BE SHOWED!)',
                        dest='debug')
    parser.add_argument('--transport-debug',
                        action='store_true', default=False,
                        help='Show traffic (PRIVATE CONTENT WILL BE SHOWED!)',
                        dest='packet_debug')

    server = parser.add_argument_group('server', 'Server side options')
    server.add_argument('-p', '--port', type=int, default=DEFAULT_SSH_PORT,
                        help='Set server port. Default: %(default)s',
                        action='store', dest='server_port')

    proxy = parser.add_argument_group('proxy', 'Proxy configuration')
    proxy.add_argument('-l', '--listen-address',
                       action='store', default=DEFAULT_LISTEN_ADDRESS,
                       help='Listen address. Default: %(default)s',
                       dest='listen_address')
    proxy.add_argument('-P', '--listen-port',
                       action='store', type=int, default=DEFAULT_LISTEN_PORT,
                       help='Listen port. Default: %(default)s',
                       dest='listen_port')
    proxy.add_argument('-k', '--key', default=DEFAULT_SERVER_KEY,
                       help='Private key for client-side handshaking. Default: %(default)s',
                       action='store', dest='private_key')
    proxy.add_argument('--server-id',
                       action='store', default=None,
                       help='Send custom server-id to clients. Default: use server id',
                       dest='server_id')
    proxy.add_argument('--user-bypass',
                       action='store', default=None,
                       help='Send this user instead of client user for authentication.',
                       dest='user_bypass')

    args = parser.parse_args()

    # Check user options
    args.private_key = os.path.expandvars(os.path.expanduser(args.private_key))
    if not os.path.exists(args.private_key):
        _ERR('Proxy key file "%s" not found!' % args.private_key)
        sys.exit(ERR_BAD_CMDLINE)

    if args.server_id is not None:
        if not args.server_id.startswith('SSH-2.0'):
            _ERR('Server identity must be begin with "SSH-2.0"')
            sys.exit(ERR_BAD_CMDLINE)

    return args


def load_key(key_file):
    '''
    Load a key file in a very quick'n'dirty way.
    You can improve it :)
    '''
    for factory in sshv2.SUPPORTED_KEYS:
        try:
            return factory(filename=key_file)
        except sshv2.SSHException:
            continue
    _WRN('Cannot determine key type of file "%s"' % key_file)


if __name__ == '__main__':
    main()
