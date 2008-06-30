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

import dbus
import gobject
import avahi
from dbus.mainloop.glib import DBusGMainLoop

# This variable is used to optionally bind to a specified
# interface.
serviceInterface = avahi.IF_UNSPEC
# It is a global variable to fit in with the rest of the
# variables from the Avahi server example code:
serviceName = "Mandos"
serviceType = "_mandos._tcp" # http://www.dns-sd.org/ServiceTypes.html
servicePort = None                      # Not known at startup
serviceTXT = []                         # TXT record for the service
domain = ""                  # Domain to publish on, default to .local
host = ""          # Host to publish records for, default to localhost
group = None #our entry group
rename_count = 12       # Counter so we only rename after collisions a
                        # sensible number of times
# End of Avahi example code


class Client(object):
    """A representation of a client host served by this server.
    Attributes:
    password:  string
    fqdn:      string, FQDN (used by the checker)
    created:   datetime.datetime()
    last_seen: datetime.datetime() or None if not yet seen
    timeout:   datetime.timedelta(); How long from last_seen until
                                     this client is invalid
    interval:  datetime.timedelta(); How often to start a new checker
    timeout_milliseconds: Used by gobject.timeout_add()
    interval_milliseconds: - '' -
    stop_hook: If set, called by stop() as stop_hook(self)
    checker:   subprocess.Popen(); a running checker process used
                                   to see if the client lives.
                                   Is None if no process is running.
    checker_initiator_tag: a gobject event source tag, or None
    stop_initiator_tag:    - '' -
    checker_callback_tag:  - '' -
    """
    def __init__(self, name=None, options=None, stop_hook=None,
                 dn=None, password=None, passfile=None, fqdn=None,
                 timeout=None, interval=-1):
        self.name = name
        self.dn = dn
        if password:
            self.password = password
        elif passfile:
            self.password = open(passfile).readall()
        else:
            raise RuntimeError(u"No Password or Passfile for client %s"
                               % self.name)
        self.fqdn = fqdn                # string
        self.created = datetime.datetime.now()
        self.last_seen = None
        if timeout is None:
            timeout = options.timeout
        self.timeout = timeout
        self.timeout_milliseconds = ((self.timeout.days
                                      * 24 * 60 * 60 * 1000)
                                     + (self.timeout.seconds * 1000)
                                     + (self.timeout.microseconds
                                        // 1000))
        if interval == -1:
            interval = options.interval
        else:
            interval = string_to_delta(interval)
        self.interval = interval
        self.interval_milliseconds = ((self.interval.days
                                       * 24 * 60 * 60 * 1000)
                                      + (self.interval.seconds * 1000)
                                      + (self.interval.microseconds
                                         // 1000))
        self.stop_hook = stop_hook
        self.checker = None
        self.checker_initiator_tag = None
        self.stop_initiator_tag = None
        self.checker_callback_tag = None
    def start(self):
        """Start this clients checker and timeout hooks"""
        # Schedule a new checker to be started an 'interval' from now,
        # and every interval from then on.
        self.checker_initiator_tag = gobject.\
                                     timeout_add(self.interval_milliseconds,
                                                 self.start_checker)
        # Also start a new checker *right now*.
        self.start_checker()
        # Schedule a stop() when 'timeout' has passed
        self.stop_initiator_tag = gobject.\
                                     timeout_add(self.timeout_milliseconds,
                                                 self.stop)
    def stop(self):
        """Stop this client.
        The possibility that this client might be restarted is left
        open, but not currently used."""
        # print "Stopping client", self.name
        self.password = None
        if self.stop_initiator_tag:
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = None
        if self.checker_initiator_tag:
            gobject.source_remove(self.checker_initiator_tag)
            self.checker_initiator_tag = None
        self.stop_checker()
        if self.stop_hook:
            self.stop_hook(self)
        # Do not run this again if called by a gobject.timeout_add
        return False
    def __del__(self):
        # Some code duplication here and in stop()
        if hasattr(self, "stop_initiator_tag") \
               and self.stop_initiator_tag:
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = None
        if hasattr(self, "checker_initiator_tag") \
               and self.checker_initiator_tag:
            gobject.source_remove(self.checker_initiator_tag)
            self.checker_initiator_tag = None
        self.stop_checker()
    def checker_callback(self, pid, condition):
        """The checker has completed, so take appropriate actions."""
        now = datetime.datetime.now()
        if os.WIFEXITED(condition) \
               and (os.WEXITSTATUS(condition) == 0):
            #print "Checker for %(name)s succeeded" % vars(self)
            self.last_seen = now
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = gobject.\
                                      timeout_add(self.timeout_milliseconds,
                                                  self.stop)
        #else:
        #    if not os.WIFEXITED(condition):
        #        print "Checker for %(name)s crashed?" % vars(self)
        #    else:
        #        print "Checker for %(name)s failed" % vars(self)
        self.checker = None
        self.checker_callback_tag = None
    def start_checker(self):
        """Start a new checker subprocess if one is not running.
        If a checker already exists, leave it running and do
        nothing."""
        if self.checker is None:
            #print "Starting checker for", self.name
            try:
                self.checker = subprocess.\
                               Popen("sleep 1; fping -q -- %s"
                                     % re.escape(self.fqdn),
                                     stdout=subprocess.PIPE,
                                     close_fds=True, shell=True,
                                     cwd="/")
                self.checker_callback_tag = gobject.\
                                            child_watch_add(self.checker.pid,
                                                            self.\
                                                            checker_callback)
            except subprocess.OSError, error:
                sys.stderr.write(u"Failed to start subprocess: %s\n"
                                 % error)
        # Re-run this periodically if run by gobject.timeout_add
        return True
    def stop_checker(self):
        """Force the checker process, if any, to stop."""
        if not hasattr(self, "checker") or self.checker is None:
            return
        gobject.source_remove(self.checker_callback_tag)
        self.checker_callback_tag = None
        os.kill(self.checker.pid, signal.SIGTERM)
        if self.checker.poll() is None:
            os.kill(self.checker.pid, signal.SIGKILL)
        self.checker = None
    def still_valid(self, now=None):
        """Has the timeout not yet passed for this client?"""
        if now is None:
            now = datetime.datetime.now()
        if self.last_seen is None:
            return now < (self.created + self.timeout)
        else:
            return now < (self.last_seen + self.timeout)


class tcp_handler(SocketServer.BaseRequestHandler, object):
    """A TCP request handler class.
    Instantiated by IPv6_TCPServer for each request to handle it.
    Note: This will run in its own forked process."""
    def handle(self):
        #print u"TCP request came"
        #print u"Request:", self.request
        #print u"Client Address:", self.client_address
        #print u"Server:", self.server
        session = gnutls.connection.ServerSession(self.request,
                                                  self.server\
                                                  .credentials)
        try:
            session.handshake()
        except gnutls.errors.GNUTLSError, error:
            #sys.stderr.write(u"Handshake failed: %s\n" % error)
            # Do not run session.bye() here: the session is not
            # established.  Just abandon the request.
            return
        #if session.peer_certificate:
        #    print "DN:", session.peer_certificate.subject
        try:
            session.verify_peer()
        except gnutls.errors.CertificateError, error:
            #sys.stderr.write(u"Verify failed: %s\n" % error)
            session.bye()
            return
        client = None
        for c in clients:
            if c.dn == session.peer_certificate.subject:
                client = c
                break
        # Have to check if client.still_valid(), since it is possible
        # that the client timed out while establishing the GnuTLS
        # session.
        if client and client.still_valid():
            session.send(client.password)
        else:
            #if client:
            #    sys.stderr.write(u"Client %(name)s is invalid\n"
            #                     % vars(client))
            #else:
            #    sys.stderr.write(u"Client not found for DN: %s\n"
            #                     % session.peer_certificate.subject)
            #session.send("gazonk")
            pass
        session.bye()


class IPv6_TCPServer(SocketServer.ForkingTCPServer, object):
    """IPv6 TCP server.  Accepts 'None' as address and/or port.
    Attributes:
        options:        Command line options
        clients:        Set() of Client objects
        credentials:    GnuTLS X.509 credentials
    """
    address_family = socket.AF_INET6
    def __init__(self, *args, **kwargs):
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
    def server_bind(self):
        """This overrides the normal server_bind() function
        to bind to an interface if one was specified, and also NOT to
        bind to an address or port if they were not specified."""
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
                    sys.stderr.write(u"Warning: No permission to bind to interface %s\n"
                                     % self.options.interface)
                else:
                    raise error
        # Only bind(2) the socket if we really need to.
        if self.server_address[0] or self.server_address[1]:
            if not self.server_address[0]:
                in6addr_any = "::"
                self.server_address = (in6addr_any,
                                       self.server_address[1])
            elif self.server_address[1] is None:
                self.server_address = (self.server_address[0],
                                       0)
            return super(type(self), self).server_bind()


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


def add_service():
    """From the Avahi server example code"""
    global group, serviceName, serviceType, servicePort, serviceTXT, \
           domain, host
    if group is None:
        group = dbus.Interface(
                bus.get_object( avahi.DBUS_NAME,
                                server.EntryGroupNew()),
                avahi.DBUS_INTERFACE_ENTRY_GROUP)
        group.connect_to_signal('StateChanged',
                                entry_group_state_changed)
    
    # print "Adding service '%s' of type '%s' ..." % (serviceName,
    #                                                 serviceType)
    
    group.AddService(
            serviceInterface,           # interface
            avahi.PROTO_INET6,          # protocol
            dbus.UInt32(0),             # flags
            serviceName, serviceType,
            domain, host,
            dbus.UInt16(servicePort),
            avahi.string_array_to_txt_array(serviceTXT))
    group.Commit()


def remove_service():
    """From the Avahi server example code"""
    global group
    
    if not group is None:
        group.Reset()


def server_state_changed(state):
    """From the Avahi server example code"""
    if state == avahi.SERVER_COLLISION:
        print "WARNING: Server name collision"
        remove_service()
    elif state == avahi.SERVER_RUNNING:
        add_service()


def entry_group_state_changed(state, error):
    """From the Avahi server example code"""
    global serviceName, server, rename_count
    
    # print "state change: %i" % state
    
    if state == avahi.ENTRY_GROUP_ESTABLISHED:
        pass
        # print "Service established."
    elif state == avahi.ENTRY_GROUP_COLLISION:
        
        rename_count = rename_count - 1
        if rename_count > 0:
            name = server.GetAlternativeServiceName(name)
            print "WARNING: Service name collision, changing name to '%s' ..." % name
            remove_service()
            add_service()
            
        else:
            print "ERROR: No suitable service name found after %i retries, exiting." % n_rename
            main_loop.quit()
    elif state == avahi.ENTRY_GROUP_FAILURE:
        print "Error in group state changed", error
        main_loop.quit()
        return


def if_nametoindex(interface):
    """Call the C function if_nametoindex()"""
    try:
        if "ctypes" not in sys.modules:
            import ctypes
        libc = ctypes.cdll.LoadLibrary("libc.so.6")
        return libc.if_nametoindex(interface)
    except (ImportError, OSError, AttributeError):
        if "struct" not in sys.modules:
            import struct
        if "fcntl" not in sys.modules:
            import fcntl
        SIOCGIFINDEX = 0x8933      # From /usr/include/linux/sockios.h
        s = socket.socket()
        ifreq = fcntl.ioctl(s, SIOCGIFINDEX,
                            struct.pack("16s16x", interface))
        s.close()
        interface_index = struct.unpack("I", ifreq[16:20])[0]
        return interface_index


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-i", "--interface", type="string",
                      default=None, metavar="IF",
                      help="Bind to interface IF")
    parser.add_option("--cert", type="string", default="cert.pem",
                      metavar="FILE",
                      help="Public key certificate PEM file to use")
    parser.add_option("--key", type="string", default="key.pem",
                      metavar="FILE",
                      help="Private key PEM file to use")
    parser.add_option("--ca", type="string", default="ca.pem",
                      metavar="FILE",
                      help="Certificate Authority certificate PEM file to use")
    parser.add_option("--crl", type="string", default="crl.pem",
                      metavar="FILE",
                      help="Certificate Revokation List PEM file to use")
    parser.add_option("-p", "--port", type="int", default=None,
                      help="Port number to receive requests on")
    parser.add_option("--timeout", type="string", # Parsed later
                      default="1h",
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
    client_config = ConfigParser.SafeConfigParser(defaults)
    #client_config.readfp(open("secrets.conf"), "secrets.conf")
    client_config.read("mandos-clients.conf")
    
    # From the Avahi server example code
    DBusGMainLoop(set_as_default=True )
    main_loop = gobject.MainLoop()
    bus = dbus.SystemBus()
    server = dbus.Interface(
            bus.get_object( avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
            avahi.DBUS_INTERFACE_SERVER )
    # End of Avahi example code
    
    clients = Set()
    def remove_from_clients(client):
        clients.remove(client)
        if not clients:
            print "No clients left, exiting"
            main_loop.quit()
    
    clients.update(Set(Client(name=section, options=options,
                              stop_hook = remove_from_clients,
                              **(dict(client_config\
                                      .items(section))))
                       for section in client_config.sections()))
    for client in clients:
        client.start()
    
    tcp_server = IPv6_TCPServer((None, options.port),
                                tcp_handler,
                                options=options,
                                clients=clients,
                                credentials=cred)
    # Find out what random port we got
    servicePort = tcp_server.socket.getsockname()[1]
    #sys.stderr.write("Now listening on port %d\n" % servicePort)
    
    if options.interface is not None:
        serviceInterface = if_nametoindex(options.interface)
    
    # From the Avahi server example code
    server.connect_to_signal("StateChanged", server_state_changed)
    server_state_changed(server.GetState())
    # End of Avahi example code
    
    gobject.io_add_watch(tcp_server.fileno(), gobject.IO_IN,
                         lambda *args, **kwargs:
                         tcp_server.handle_request(*args[2:],
                                                   **kwargs) or True)
    try:
        main_loop.run()
    except KeyboardInterrupt:
        print
    
    # Cleanup here

    # From the Avahi server example code
    if not group is None:
        group.Free()
    # End of Avahi example code
    
    for client in clients:
        client.stop_hook = None
        client.stop()
