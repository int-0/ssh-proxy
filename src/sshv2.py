#!/usr/bin/env python
'''
SSHv2 Proxy classes
'''

__version__ = '0.0.1'
__author__ = 'Tobias Diaz'
__email__ = 'tobias.deb@gmail.com'
__license__ = 'GPLv3'

import socket
import logging
import tempfile
import threading
import traceback

import paramiko
import paramiko.server
from paramiko import SSHException

# Logging
_DEB = logging.debug
_ERR = logging.error
_WRN = logging.warning
logging.getLogger("paramiko").setLevel(logging.WARNING)

# Lib config
BACKLOG_SIZE = 128
BUFFER_SIZE = 2048
SUPPORTED_KEYS = [paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey]


class ProxyError(Exception):
    '''
    Generic exception used to quit inmediatly
    '''
    pass


class TunnelHandler(threading.Thread):
    '''
    This class do the magic: is a composition of two paramiko transport objects,
    one in server mode (self.client) and other in client mode (self.server).
    When server side get a client request, it is handled in this class and
    forwarded to the server is needed.
    '''
    def __init__(self, server_address, server_key, connection, tunnel_config):
        super(TunnelHandler, self).__init__()
        _DEB('Making new SSHv2 tunnel from %s to %s' % (
            connection.getsockname(), server_address))

        self._tunnel_config = tunnel_config

        self.server = ServerHandler(server_address)
        self.client = paramiko.Transport(connection, gss_kex=True)
        if self._tunnel_config.packet_debug:
            self.client.set_hexdump(True)
        self.client.set_gss_host(socket.getfqdn(""))

        try:
            self.client.load_server_moduli()
        except Exception as error:
            _WRN('Failed to load moduli(gex will be unsupported): %s' % error)
            raise
        self.client.add_server_key(server_key)
        self.client.local_version = tunnel_config.server_id
        try:
            self.client.start_server(
                server=ClientHandler(self))
        except paramiko.SSHException as error:
            _WRN('SSH negotiation failed: %s' % error)
            raise
        self._shutdown = threading.Event()
        self.start()

    @property
    def config(self):
        '''Return TunnelConfig() object'''
        return self._tunnel_config

    def auth_password(self, username, password):
        '''Forward a password-prompt auth request'''
        _DEB('user: %s' % username)
        _DEB('bypass: %s' % self.config.user)
        username = self.config.user or username
        if self.server.auth_password(username, password):
            _DEB('Authentication passed!')
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def auth_publickey(self, username, key):
        '''Forward a publickey auth request'''
        username = self.config.user or username
        keyfile = tempfile.NamedTemporaryFile(delete=False)
        #keyfile.write(bytes(str(key), 'utf-8'))
        keyfile.write(bytes(str(key)))
        keyfile.close()
        _DEB('Key recived, saved to: %s' % keyfile.name)
        if self.server.auth_publickey(username, keyfile.name):
            _DEB('Authentication passed!')
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def channel_request(self, kind, chanid):
        '''Forward a new channel request'''
        return self.server.channel_request(kind, chanid)

    def channel_pty_request(self, channel, term, width, height,
                            pixelwidth, pixelheight, modes):
        '''Forward a pty channel request'''
        server_response = self.server.channel_pty_request(channel,
                                                          term,
                                                          width, height,
                                                          pixelwidth,
                                                          pixelheight,
                                                          modes)
        ChannelForward(self.server.channels[channel.chanid], channel)
        _DEB('Server says: %s' % server_response)
        return server_response

    def channel_window_change_request(self, channel, width, height,
                                      pixelwidth, pixelheight):
        '''Forward a change_window channel request'''
        return self.server.channel_window_change_request(
            channel, width, height, pixelwidth, pixelheight)

    def channel_shell_request(self, channel):
        '''Forward a shell channel request'''
        return self.server.channel_shell_request(channel)

    def channel_exec(self, channel, cmd):
        '''Forward a exec channel request'''
        server_response = self.server.channel_exec(channel, cmd)
        if server_response:
            ChannelForward(self.server.channels[channel.chanid], channel)
        return  server_response

    def channel_x11_request(self, channel, single_connection,
                            auth_protocol, auth_cookie, screen_number):
        '''Forward X11 channel request'''
        return self.server.channel_x11_request(channel,
                                               single_connection,
                                               auth_protocol,
                                               auth_cookie,
                                               screen_number,
                                               self._new_x11_fw_)

    def _new_x11_fw_(self, channel, address):
        '''Open channel and make it forwarded'''
        x11_channel = self.client.open_x11_channel(address)
        ChannelForward(x11_channel, channel)

    def run(self):
        '''Wait until shutdown'''
        self._shutdown.wait()

    def kill(self):
        '''Shutdown'''
        _DEB('Killing tunnel...')
        self._shutdown.set()


class ServerHandler(object):
    '''
    This class make SSHv2 connection to a remote server (is a client),
    and make requests forwarded by the tunnel.
    '''
    def __init__(self, server_address):
        self._server_hostname, self._server_port = server_address
        self._ssh = None
        self.channels = {}

    def auth_password(self, username, password):
        '''Try to connect to server with password-based auth'''
        _DEB('Requesting password-based authentication')
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._ssh.connect(hostname=self._server_hostname,
                              port=self._server_port,
                              username=username,
                              password=password)
            return True
        except paramiko.BadHostKeyException:
            _ERR('Remote server has an invalid key')
        except paramiko.AuthenticationException:
            _WRN('Server rejects user/password')
        except paramiko.SSHException as error:
            _WRN('SSH error: %s' % error)
        else:
            _ERR('Unhandled error')
            traceback.print_exc()
        self._ssh = None
        return False

    def auth_publickey(self, username, key):
        '''Try to connect to server with publickey-based auth'''
        _DEB('Requesting key-based authentication')
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._ssh.connect(hostname=self._server_hostname,
                              port=self._server_port,
                              username=username,
                              key_filename=key)
            return True
        except paramiko.BadHostKeyException:
            _ERR('Remote server has an invalid key')
        except paramiko.AuthenticationException:
            _WRN('Server rejects user/password')
        except paramiko.SSHException as error:
            _WRN('SSH error: %s' % error)
        else:
            _ERR('Unhandled error')
            traceback.print_exc()
        self._ssh = None
        return False

    def channel_request(self, kind, chanid):
        '''Try to open new channel to server'''
        if self._ssh is None:
            _WRN('Channel requested but no connection made')
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.channels[chanid] = self._ssh.get_transport().open_channel(kind)
        if self.channels[chanid] is None:
            _DEB('Cannot create a channel of type "%s"' % kind)
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        _DEB('Channel %s created as type %s' % (chanid, kind))
        return paramiko.OPEN_SUCCEEDED

    def channel_pty_request(self, channel, term, width, height,
                            pixelwidth, pixelheight, modes):
        '''Try to request pty on a previous-created channel'''
        if self._ssh is None:
            _WRN('pty requested but no connection made')
            return False
        if channel.chanid not in self.channels.keys():
            _WRN('Undefined channel for pty request')
            return False
        self.channels[channel.chanid].event.set()
        self.channels[channel.chanid].get_pty(term,
                                              width, height,
                                              pixelwidth, pixelheight)
        _DEB('pty requested for channel %s completed' % channel.chanid)
        return True

    def channel_window_change_request(self, channel, width, height,
                                      pixelwidth, pixelheight):
        '''Send window_change request to server'''
        if self._ssh is None:
            _WRN('window_change requested but no connection made')
            return False
        if channel.chanid not in self.channels.keys():
            _WRN('Undefined channel for window_change request')
            return False
        try:
            self.channels[channel.chanid].resize_pty(
                width, height, pixelwidth, pixelheight)
            _DEB('window_change request for chanel %s completed' % (
                channel.chanid))
            return True
        except paramiko.SSHException as error:
            _WRN('Unable to resize window: %s' % error)
        else:
            _ERR('Unhandled error')
            traceback.print_exc()
        return False

    def channel_shell_request(self, channel):
        '''Send shell request to server'''
        if self._ssh is None:
            _WRN('Shell requested but no connection made')
            return False
        if channel.chanid not in self.channels.keys():
            _WRN('Undefined channel for shell request')
            return False
        self.channels[channel.chanid].invoke_shell()
        _DEB('Shell invoked in channel %s' % channel.chanid)
        return True

    def channel_exec(self, channel, cmd):
        '''Send exec to server'''
        if self._ssh is None:
            _WRN('exec requested but no connection made')
            return False
        if channel.chanid not in self.channels.keys():
            _WRN('Undefined channel for exec')
            return False
        try:
            self.channels[channel.chanid].exec_command(cmd)
            _DEB('exec(%s) on channel %s completed' % (cmd, channel.chanid))
            return True
        except paramiko.SSHException as error:
            _WRN('Unable to exec(%s): %s' % (cmd, error))
        else:
            _ERR('Unhandled error')
            traceback.print_exc()
            return False

    def channel_x11_request(self, channel, single_connection,
                            auth_protocol, auth_cookie, screen_number,
                            new_x11conn_handler):
        '''Send x11 channel request to server'''
        if self._ssh is None:
            _WRN('X11 forwarding requested but no connection made')
            return False
        if channel.chanid not in self.channels.keys():
            _WRN('Undefined channel for X11 forwarding request')
            return False
        auth = self.channels[channel.chanid].request_x11(
            screen_number,
            auth_protocol,
            auth_cookie,
            single_connection, new_x11conn_handler)
        _DEB('X11 forwarding request completed for channel %s' % channel.chanid)
        return auth


class ClientHandler(paramiko.server.ServerInterface):
    '''
    This class accepts SSHv2 connection from the client (is a server),
    accepts requests,  some are handled directly and others are forwarded to
    the parent tunnel.
    '''
    def __init__(self, tunnel):
        super(ClientHandler, self).__init__()
        self.remote = tunnel

    def check_auth_password(self, username, password):
        _DEB('auth_password(%s, <password>) received' % username)
        return self.remote.auth_password(username, password)

    def check_auth_publickey(self, username, key):
        _DEB('auth_publickey(%s, <key>) received' % username)
        return self.remote.auth_publickey(username, key)

    def check_auth_gssapi_with_mic(self, username,
                                   gss_authenticated=paramiko.AUTH_FAILED,
                                   cc_file=None):
        _DEB('auth_gssapi_with_mic(%s) received' % username)
        # This is unsecure because user authentication with krb5 is not checked
        # but for the proxy it doesn't matters ;)
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username,
                                gss_authenticated=paramiko.AUTH_FAILED,
                                cc_file=None):
        _DEB('auth_gssapi_keyex(%s) received' % username)
        # This is unsecure because user authentication with krb5 is not checked
        # but for the proxy it doesn't matters ;)
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        _DEB('enable_auth_gssapi() received')
        # This is like "yes-to-all" :)
        return True

    def get_allowed_auths(self, username):
        _DEB('allowed_auths(%s) received' % username)
        # This is like "yes-to-all" :)
        return 'gssapi-keyex,gssapi-with-mic,password,publickey'

    def check_channel_request(self, kind, chanid):
        _DEB('channel_request(%s, %s) received' % (kind, chanid))
        return self.remote.channel_request(kind, chanid)

    def check_channel_subsystem_request(self, channel, name):
        _DEB('channel_subsystem_request(%s, %s) received' % (channel, name))
        return self.remote.channel_subsystem(channel, name)

    def check_channel_exec_request(self, channel, command):
        _DEB('channel_exec_request(%s, %s) received' % (channel.chanid,
                                                        command))
        return self.remote.channel_exec(channel, command)

    def check_channel_shell_request(self, channel):
        _DEB('channel_shell_request(%s) received' % (channel))
        return self.remote.channel_shell_request(channel)

    def check_channel_pty_request(self, channel, term,
                                  width, height,
                                  pixelwidth, pixelheight,
                                  modes):
        _DEB('channel_pty_request(%s, %s, %s, %s, %s, %s) received' % (
            channel.chanid, term, width, height, pixelwidth, pixelheight))
        return self.remote.channel_pty_request(channel,
                                               term, width, height,
                                               pixelwidth, pixelheight,
                                               modes)

    def check_channel_window_change_request(self, channel, width, height,
                                            pixelwidth, pixelheight):
        _DEB('channel_window_change_request(%s, %s, %s, %s, %s) received' % (
            channel.chanid, width, height, pixelwidth, pixelheight))
        return self.remote.channel_window_change_request(
            channel, width, height, pixelwidth, pixelheight)

    def check_channel_x11_request(self, channel, single_connection,
                                  auth_protocol, auth_cookie, screen_number):
        _DEB('channel_x11_request(%s, %s, %s, %s, %s) received' % (
            channel, single_connection,
            auth_protocol, auth_cookie, screen_number))
        return self.remote.channel_x11_request(channel,
                                               single_connection,
                                               auth_protocol,
                                               auth_cookie,
                                               screen_number)
    # NOT IMPLEMENTED YET
    # def check_global_request(self, kind, msg):
    #     _DEB('global_request(%s, %s) received' % (kind, msg))
    #     return self.remote.global_request(kind, msg)
    #
    # def check_port_forward_request(self, address, port):
    #     _DEB('port_forward_request(%s, %s) received' % (address, port))
    #     return self.remote.port_forward_request(address, port)


def forward(ep1, ep2):
    '''Forward one buffer from ep1 to ep2'''
    stdout = stderr = status = None
    if ep1.exit_status_ready():
        status = ep1.recv_exit_status()
        ep2.send_exit_status(status)
    if ep1.recv_ready():
        stdout = ep1.recv(BUFFER_SIZE)
        ep2.send(stdout)
    if ep1.recv_stderr_ready():
        stderr = ep1.recv_stderr(BUFFER_SIZE)
        ep2.send_stderr(stderr)
    return (stdout, stderr, status)


class ChannelForward(threading.Thread):
    '''
    This class is a quick'n'dirty (again) channel forwarder. Just
    read from one channel and send all to the other. In both directions.
    '''
    def __init__(self, server_channel, client_channel):
        super(ChannelForward, self).__init__()
        self.server = server_channel
        self.client = client_channel
        self.client.event = self.server.event
        self.start()

    @property
    def _both_sides_open_(self):
        return ((self.server.active and not self.server.closed) and
                (self.client.active and not self.client.closed))

    def run(self):
        _DEB('Start channel forwarding %s to %s' % (self.server, self.client))
        while self._both_sides_open_:
            server_say = forward(self.server, self.client)
            if any(data is not None for data in server_say):
                _DEB('Server: %s' % repr(server_say))
            client_say = forward(self.client, self.server)
            if any(data is not None for data in client_say):
                _DEB('Client: %s' % repr(client_say))

            # Check EOFs and send remaining
            if self.server.eof_received:
                _WRN('EOF received from server...')
                forward(self.server, self.client)
                self.client.shutdown(2)
            if self.client.eof_received:
                _WRN('EOF received from client...')
                forward(self.client, self.server)
                self.server.shutdown(2)

        _DEB('Stop channel forwarding %s to %s' % (self.server, self.client))
        if not self.server.closed:
            self.server.close()
        if not self.client.closed:
            self.client.close()


class SimpleSocketServer(object):
    '''
    Yep... standard SocketServer() does not configure sockets properly for SSH
    and I prefer to waste time with SSHv2 protocol instead of SocketServer()
    internals :p
    '''
    def __init__(self, myaddress, foreignaddress, foreignkey, tunnel_config):
        self._server_address = foreignaddress
        self._server_key = foreignkey
        self._tunnel_config = tunnel_config

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(myaddress)
            self._sock.listen(BACKLOG_SIZE)
        except socket.error as error:
            _ERR('Unable to listen in %s:%s' % myaddress)
            _ERR('Error: %s' % error)
            raise ProxyError()
        _DEB('Listening in %s:%s...' % myaddress)

    def serve_forever(self):
        '''Accept connections until Ctrl-C'''
        bad_exit = False
        tunnels = []
        while True:
            try:
                client, addr = self._sock.accept()
                _DEB('Accepted new connection from %s:%s' % addr)
                tunnels.append(TunnelHandler(self._server_address,
                                             self._server_key, client,
                                             self._tunnel_config))
            except KeyboardInterrupt:
                _WRN('User want to quit...')
                break
            except Exception as error:
                _ERR('Unexpected error: %s' % error)
                traceback.print_exc()
                bad_exit = True
                break

        _DEB('Shutting down...')
        self._sock.close()
        for tunnel in tunnels:
            tunnel.kill()
            tunnel.join()

        if bad_exit:
            raise ProxyError()


def detect_server_id(server_endpoint):
    '''
    Connect to remote server just to get the ID
    '''
    hostname, port = server_endpoint

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=hostname, port=port,
                    username='', password='')
    except paramiko.BadHostKeyException:
        _ERR('Remote server has an invalid key')
        raise ProxyError()
    except (paramiko.AuthenticationException,
            paramiko.SSHException):
        pass
    _DEB('Remote server ID: %s' % ssh.get_transport().remote_version)
    return ssh.get_transport().remote_version
