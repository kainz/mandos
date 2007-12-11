#!/usr/bin/python

import SocketServer
import socket
import select
from optparse import OptionParser
import datetime
import errno
import gnutls.crypto
import gnutls.connection
import gnutls.errors
import ConfigParser

class Client(object):
    def __init__(self, name=None, dn=None, password=None,
                 passfile=None, fqdn=None, timeout=None,
                 interval=-1):
        self.name = name
        self.dn = dn
        if password:
            self.password = password
        elif passfile:
            self.password = open(passfile).readall()
        else:
            print "No Password or Passfile in client config file"
            # raise RuntimeError XXX
            self.password = "gazonk"
        self.fqdn = fqdn
        # self.created = ...
        self.last_seen = None
        if timeout is None:
            timeout = self.server.options.timeout
        self.timeout = timeout
        if interval == -1:
            interval = self.server.options.interval
        self.interval = interval

def server_bind(self):
    if self.options.interface:
        if not hasattr(socket, "SO_BINDTODEVICE"):
            # From /usr/include/asm-i486/socket.h
            socket.SO_BINDTODEVICE = 25
        try:
            self.socket.setsockopt(socket.SOL_SOCKET,
                                   socket.SO_BINDTODEVICE,
                                   self.options.interface)
        except socket.error, error:
            if error[0] == errno.EPERM:
                print "Warning: Denied permission to bind to interface", \
                      self.options.interface
            else:
                raise error
    return super(type(self), self).server_bind()


def init_with_options(self, *args, **kwargs):
    if "options" in kwargs:
        self.options = kwargs["options"]
        del kwargs["options"]
    if "clients" in kwargs:
        self.clients = kwargs["clients"]
        del kwargs["clients"]
    if "credentials" in kwargs:
        self.credentials = kwargs["credentials"]
        del kwargs["credentials"]
    return super(type(self), self).__init__(*args, **kwargs)


class udp_handler(SocketServer.DatagramRequestHandler, object):
    def handle(self):
        self.wfile.write("Polo")
        print "UDP request answered"


class IPv6_UDPServer(SocketServer.UDPServer, object):
    __init__ = init_with_options
    address_family = socket.AF_INET6
    allow_reuse_address = True
    server_bind = server_bind
    def verify_request(self, request, client_address):
        print "UDP request came"
        return request[0] == "Marco"


class tcp_handler(SocketServer.BaseRequestHandler, object):
    def handle(self):
        print "TCP request came"
        print "Request:", self.request
        print "Client Address:", self.client_address
        print "Server:", self.server
        session = gnutls.connection.ServerSession(self.request,
                                                  self.server.credentials)
        session.handshake()
        if session.peer_certificate:
            print "DN:", session.peer_certificate.subject
        try:
            session.verify_peer()
        except gnutls.errors.CertificateError, error:
            print "Verify failed", error
            session.bye()
            return
        try:
            session.send(dict((client.dn, client.password)
                              for client in self.server.clients)
                         [session.peer_certificate.subject])
        except KeyError:
            session.send("gazonk")
            # Log maybe? XXX
        session.bye()

class IPv6_TCPServer(SocketServer.ForkingTCPServer, object):
    __init__ = init_with_options
    address_family = socket.AF_INET6
    allow_reuse_address = True
    request_queue_size = 1024
    server_bind = server_bind


in6addr_any = "::"

cred = None

def main():
    parser = OptionParser()
    parser.add_option("-i", "--interface", type="string",
                      default="eth0", metavar="IF",
                      help="Interface to bind to")
    parser.add_option("--cert", type="string", default="cert.pem",
                      metavar="FILE",
                      help="Public key certificate to use")
    parser.add_option("--key", type="string", default="key.pem",
                      metavar="FILE",
                      help="Private key to use")
    parser.add_option("--ca", type="string", default="ca.pem",
                      metavar="FILE",
                      help="Certificate Authority certificate to use")
    parser.add_option("--crl", type="string", default="crl.pem",
                      metavar="FILE",
                      help="Certificate Revokation List to use")
    parser.add_option("-p", "--port", type="int", default=49001,
                      help="Port number to receive requests on")
    parser.add_option("--dh", type="int", metavar="BITS",
                      help="DH group to use")
    parser.add_option("-t", "--timeout", type="string", # Parsed later
                      default="15m",
                      help="Amount of downtime allowed for clients")
    (options, args) = parser.parse_args()
    
    # Parse the time argument
    try:
        suffix=options.timeout[-1]
        value=int(options.timeout[:-1])
        if suffix == "d":
            options.timeout = datetime.timedelta(value)
        elif suffix == "s":
            options.timeout = datetime.timedelta(0, value)
        elif suffix == "m":
            options.timeout = datetime.timedelta(0, 0, 0, 0, value)
        elif suffix == "h":
            options.timeout = datetime.timedelta(0, 0, 0, 0, 0, value)
        elif suffix == "w":
            options.timeout = datetime.timedelta(0, 0, 0, 0, 0, 0,
                                                 value)
        else:
            raise ValueError
    except (ValueError, IndexError):
        parser.error("option --timeout: Unparseable time")
    
    cert = gnutls.crypto.X509Certificate(open(options.cert).read())
    key = gnutls.crypto.X509PrivateKey(open(options.key).read())
    ca = gnutls.crypto.X509Certificate(open(options.ca).read())
    crl = gnutls.crypto.X509CRL(open(options.crl).read())
    cred = gnutls.connection.X509Credentials(cert, key, [ca], [crl])
    
    # Parse config file
    defaults = {}
    client_config_object = ConfigParser.SafeConfigParser(defaults)
    client_config_object.read("mandos-clients.conf")
    clients = [Client(name=section,
                      **(dict(client_config_object.items(section))))
               for section in client_config_object.sections()]
    
    udp_server = IPv6_UDPServer((in6addr_any, options.port),
                                udp_handler,
                                options=options)
    
    tcp_server = IPv6_TCPServer((in6addr_any, options.port),
                                tcp_handler,
                                options=options,
                                clients=clients,
                                credentials=cred)
    
    while True:
        in_, out, err = select.select((udp_server,
                                       tcp_server), (), ())
        for server in in_:
            server.handle_request()


if __name__ == "__main__":
    main()

