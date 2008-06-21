#!/usr/bin/python

from __future__ import division

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
import sys
import re
import os
import signal
from sets import Set
import subprocess

class Client(object):
    def __init__(self, name=None, options=None, dn=None,
                 password=None, passfile=None, fqdn=None,
                 timeout=None, interval=-1):
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
        self.fqdn = fqdn                # string
        self.created = datetime.datetime.now()
        self.last_seen = None           # datetime.datetime()
        if timeout is None:
            timeout = options.timeout
        self.timeout = timeout          # datetime.timedelta()
        if interval == -1:
            interval = options.interval
        else:
            interval = string_to_delta(interval)
        self.interval = interval        # datetime.timedelta()
        self.next_check = datetime.datetime.now() # datetime.datetime()
        # Note: next_check may be in the past if checker is not None
        self.checker = None             # or a subprocess.Popen()
    def check_action(self):
        """The checker said something and might have completed.
        Check if is has, and take appropriate actions."""
        if self.checker.poll() is None:
            # False alarm, no result yet
            #self.checker.read()
            #print "Checker for %(name)s said nothing?" % vars(self)
            return
        now = datetime.datetime.now()
        if self.checker.returncode == 0:
            print "Checker for %(name)s succeeded" % vars(self)
            self.last_seen = now
        else:
            print "Checker for %(name)s failed" % vars(self)
        while self.next_check <= now:
            self.next_check += self.interval
        self.checker = None
    handle_request = check_action
    def start_checker(self):
        self.stop_checker()
        try:
            self.checker = subprocess.Popen("sleep 10; fping -q -- %s"
                                            % re.escape(self.fqdn),
                                            stdout=subprocess.PIPE,
                                            close_fds=True,
                                            shell=True, cwd="/")
        except subprocess.OSError, e:
            print "Failed to start subprocess:", e
    def stop_checker(self):
        if self.checker is None:
            return
        os.kill(self.checker.pid, signal.SIGTERM)
        if self.checker.poll() is None:
            os.kill(self.checker.pid, signal.SIGKILL)
        self.checker = None
    __del__ = stop_checker
    def fileno(self):
        if self.checker is None:
            return None
        return self.checker.stdout.fileno()
    def next_stop(self):
        """The time when something must be done about this client
        May be in the past."""
        if self.last_seen is None:
            # This client has never been seen
            next_timeout = self.created + self.timeout
        else:
            next_timeout = self.last_seen + self.timeout
        if self.checker is None:
            return min(next_timeout, self.next_check)
        else:
            return next_timeout
    def still_valid(self, now=None):
        """Has this client's timeout not passed?"""
        if now is None:
            now = datetime.datetime.now()
        if self.last_seen is None:
            return now < (self.created + self.timeout)
        else:
            return now < (self.last_seen + self.timeout)
    def it_is_time_to_check(self, now=None):
        if now is None:
            now = datetime.datetime.now()
        return self.next_check <= now


class server_metaclass(type):
    "Common behavior for the UDP and TCP server classes"
    def __new__(cls, name, bases, attrs):
        attrs["address_family"] = socket.AF_INET6
        attrs["allow_reuse_address"] = True
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
                        print "Warning: No permission to bind to interface", \
                              self.options.interface
                    else:
                        raise error
            return super(type(self), self).server_bind()
        attrs["server_bind"] = server_bind
        def init(self, *args, **kwargs):
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
        attrs["__init__"] = init
        return type.__new__(cls, name, bases, attrs)


class udp_handler(SocketServer.DatagramRequestHandler, object):
    def handle(self):
        self.wfile.write("Polo")
        print "UDP request answered"


class IPv6_UDPServer(SocketServer.UDPServer, object):
    __metaclass__ = server_metaclass
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
            session.send([client.password
                          for client in self.server.clients
                          if (client.dn ==
                              session.peer_certificate.subject)][0])
        except IndexError:
            session.send("gazonk")
            # Log maybe? XXX
        session.bye()


class IPv6_TCPServer(SocketServer.ForkingTCPServer, object):
    __metaclass__ = server_metaclass


def string_to_delta(interval):
    """Parse a string and return a datetime.timedelta

    >>> string_to_delta('7d')
    datetime.timedelta(7)
    >>> string_to_delta('60s')
    datetime.timedelta(0, 60)
    >>> string_to_delta('60m')
    datetime.timedelta(0, 3600)
    >>> string_to_delta('24h')
    datetime.timedelta(1)
    >>> string_to_delta(u'1w')
    datetime.timedelta(7)
    """
    try:
        suffix=unicode(interval[-1])
        value=int(interval[:-1])
        if suffix == u"d":
            delta = datetime.timedelta(value)
        elif suffix == u"s":
            delta = datetime.timedelta(0, value)
        elif suffix == u"m":
            delta = datetime.timedelta(0, 0, 0, 0, value)
        elif suffix == u"h":
            delta = datetime.timedelta(0, 0, 0, 0, 0, value)
        elif suffix == u"w":
            delta = datetime.timedelta(0, 0, 0, 0, 0, 0, value)
        else:
            raise ValueError
    except (ValueError, IndexError):
        raise ValueError
    return delta


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
    parser.add_option("--interval", type="string", # Parsed later
                      default="5m",
                      help="How often to check that a client is up")
    parser.add_option("--check", action="store_true", default=False,
                      help="Run self-test")
    (options, args) = parser.parse_args()

    if options.check:
        import doctest
        doctest.testmod()
        sys.exit()
    
    # Parse the time arguments
    try:
        options.timeout = string_to_delta(options.timeout)
    except ValueError:
        parser.error("option --timeout: Unparseable time")
    
    try:
        options.interval = string_to_delta(options.interval)
    except ValueError:
        parser.error("option --interval: Unparseable time")
    
    cert = gnutls.crypto.X509Certificate(open(options.cert).read())
    key = gnutls.crypto.X509PrivateKey(open(options.key).read())
    ca = gnutls.crypto.X509Certificate(open(options.ca).read())
    crl = gnutls.crypto.X509CRL(open(options.crl).read())
    cred = gnutls.connection.X509Credentials(cert, key, [ca], [crl])
    
    # Parse config file
    defaults = {}
    client_config_object = ConfigParser.SafeConfigParser(defaults)
    client_config_object.read("mandos-clients.conf")
    clients = Set(Client(name=section, options=options,
                         **(dict(client_config_object\
                                 .items(section))))
                  for section in client_config_object.sections())
    
    in6addr_any = "::"
    udp_server = IPv6_UDPServer((in6addr_any, options.port),
                                udp_handler,
                                options=options)
    
    tcp_server = IPv6_TCPServer((in6addr_any, options.port),
                                tcp_handler,
                                options=options,
                                clients=clients,
                                credentials=cred)
    
    while True:
        if not clients:
            break
        try:
            next_stop = min(client.next_stop() for client in clients)
            now = datetime.datetime.now()
            if next_stop > now:
                delay = next_stop - now
                delay_seconds = (delay.days * 24 * 60 * 60
                                 + delay.seconds
                                 + delay.microseconds / 1000000)
                clients_with_checkers = tuple(client for client in
                                              clients
                                              if client.checker
                                              is not None)
                input_checks = (udp_server, tcp_server) \
                               + clients_with_checkers
                print "Waiting for network",
                if clients_with_checkers:
                    print "and checkers for:",
                    for client in clients_with_checkers:
                        print client.name,
                print
                input, out, err = select.select(input_checks, (), (),
                                                delay_seconds)
                for obj in input:
                    obj.handle_request()
            # start new checkers
            for client in clients:
                if client.it_is_time_to_check(now=now) and \
                       client.checker is None:
                    print "Starting checker for client %(name)s" \
                          % vars(client)
                    client.start_checker()
            # delete timed-out clients
            for client in clients.copy():
                if not client.still_valid(now=now):
                    # log xxx
                    print "Removing client %(name)s" % vars(client)
                    clients.remove(client)
        except KeyboardInterrupt:
            break
    
    # Cleanup here
    for client in clients:
        client.stop_checker()


if __name__ == "__main__":
    main()

