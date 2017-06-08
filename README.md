# SSHv2 Server proxy

This is an example of SSHv2 proxy server written in python. At the moment it
supports password-based and publickey authentication. About the transport,
shell and X11 channels are supported.

*Don't use this proxy in production networks*, the purpose of this program
is pure educational.

## How it works

This proxy listen for a SSH clients connections and handle his requests.
Some requests are forwarded to a real SSH server and some others are
resolved in the proxy. This is **dangerous** (or _funny_, depends of your POV)
because all data is handled by the proxy is raw format (without encryption).
This allows logging, injection... all MitM adventages (again, for educational
purposes).

## Supported traffic types

I check with standard remote shells, X11 forwarding channels and commands like
_scp_.

The following features are *NOT* supported (but it can be added easily):
* SSHv2 subsystems
* port forwarding
* SFTP

## How to use

The usage it's very easy (I hope):

```
usage: ssh-proxy [-h] [--version] [--debug] [--transport-debug]
                 [-p SERVER_PORT] [-l LISTEN_ADDRESS] [-P LISTEN_PORT]
                 [-k PRIVATE_KEY] [--server-id SERVER_ID]
                 [--user-bypass USER_BYPASS]
                 SERVER

Make a SSHv2 server proxy.

positional arguments:
  SERVER                Server to forward connections to

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --debug               Be verbose (PRIVATE CONTENT CAN BE SHOWED!)
  --transport-debug     Show traffic (PRIVATE CONTENT WILL BE SHOWED!)

server:
  Server side options

  -p SERVER_PORT, --port SERVER_PORT
                        Set server port. Default: 22

proxy:
  Proxy configuration

  -l LISTEN_ADDRESS, --listen-address LISTEN_ADDRESS
                        Listen address. Default: 0.0.0.0
  -P LISTEN_PORT, --listen-port LISTEN_PORT
                        Listen port. Default: 2200
  -k PRIVATE_KEY, --key PRIVATE_KEY
                        Private key for client-side handshaking. Default:
                        $HOME/.ssh/id_rsa
  --server-id SERVER_ID
                        Send custom server-id to clients. Default: use server
                        id
  --user-bypass USER_BYPASS
                        Send this user instead of client user for
                        authentication.
```

## Examples:

For the basic usage you need a SSH server, for example in your own machine.
In that case you can connect to your server throught the proxy just
run the proxy with the following command:

```bash
./ssh-proxy localhost
```
And then, connect the client:
```bash
ssh -p 2200 localhost
```

Server id is bypassed by default, but you can force any id. This could be
useful to check if you are connected via proxy or direct:

```bash
./ssh-proxy --server-id "SSH-2.0-OpenSSH Proxy"
```
Show _debug1_ messages to check the server id:

```bash
./ssh -p 2200 -v localhost
OpenSSH_7.4p1 Debian-10, OpenSSL 1.0.2k  26 Jan 2017
debug1: Reading configuration data /home/tobias/.ssh/config
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: Applying options for *
debug1: Connecting to localhost [::1] port 2200.
debug1: connect to address ::1 port 2200: Connection refused
debug1: Connecting to localhost [127.0.0.1] port 2200.
debug1: Connection established.

bla bla bla

debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_7.4p1 Debian-10
debug1: Remote protocol version 2.0, remote software version OpenSSH Proxy
debug1: match: OpenSSH Proxy pat OpenSSH* compat 0x04000000
```