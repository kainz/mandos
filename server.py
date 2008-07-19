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
import gnutls.library.functions
import gnutls.library.constants
import gnutls.library.types
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
import ctypes

# This variable is used to optionally bind to a specified interface.
# It is a global variable to fit in with the other variables from the
# Avahi server example code.
serviceInterface = avahi.IF_UNSPEC
# From the Avahi server example code:
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
    name:      string; from the config file, used in log messages
    fingerprint: string (40 or 32 hexadecimal digits); used to
                 uniquely identify the client
    secret:    bytestring; sent verbatim (over TLS) to client
    fqdn:      string (FQDN); available for use by the checker command
    created:   datetime.datetime()
    last_seen: datetime.datetime() or None if not yet seen
    timeout:   datetime.timedelta(); How long from last_seen until
                                     this client is invalid
    interval:  datetime.timedelta(); How often to start a new checker
    stop_hook: If set, called by stop() as stop_hook(self)
    checker:   subprocess.Popen(); a running checker process used
                                   to see if the client lives.
                                   Is None if no process is running.
    checker_initiator_tag: a gobject event source tag, or None
    stop_initiator_tag:    - '' -
    checker_callback_tag:  - '' -
    checker_command: string; External command which is run to check if
                     client lives.  %()s expansions are done at
                     runtime with vars(self) as dict, so that for
                     instance %(name)s can be used in the command.
    Private attibutes:
    _timeout: Real variable for 'timeout'
    _interval: Real variable for 'interval'
    _timeout_milliseconds: Used by gobject.timeout_add()
    _interval_milliseconds: - '' -
    """
    def _set_timeout(self, timeout):
        "Setter function for 'timeout' attribute"
        self._timeout = timeout
        self._timeout_milliseconds = ((self.timeout.days
                                       * 24 * 60 * 60 * 1000)
                                      + (self.timeout.seconds * 1000)
                                      + (self.timeout.microseconds
                                         // 1000))
    timeout = property(lambda self: self._timeout,
                       _set_timeout)
    del _set_timeout
    def _set_interval(self, interval):
        "Setter function for 'interval' attribute"
        self._interval = interval
        self._interval_milliseconds = ((self.interval.days
                                        * 24 * 60 * 60 * 1000)
                                       + (self.interval.seconds
                                          * 1000)
                                       + (self.interval.microseconds
                                          // 1000))
    interval = property(lambda self: self._interval,
                        _set_interval)
    del _set_interval
    def __init__(self, name=None, options=None, stop_hook=None,
                 fingerprint=None, secret=None, secfile=None, fqdn=None,
                 timeout=None, interval=-1, checker=None):
        self.name = name
        # Uppercase and remove spaces from fingerprint
        # for later comparison purposes with return value of
        # the fingerprint() function
        self.fingerprint = fingerprint.upper().replace(u" ", u"")
        if secret:
            self.secret = secret.decode(u"base64")
        elif secfile:
            sf = open(secfile)
            self.secret = sf.read()
            sf.close()
        else:
            raise RuntimeError(u"No secret or secfile for client %s"
                               % self.name)
        self.fqdn = fqdn                # string
        self.created = datetime.datetime.now()
        self.last_seen = None
        if timeout is None:
            timeout = options.timeout
        self.timeout = timeout
        if interval == -1:
            interval = options.interval
        else:
            interval = string_to_delta(interval)
        self.interval = interval
        self.stop_hook = stop_hook
        self.checker = None
        self.checker_initiator_tag = None
        self.stop_initiator_tag = None
        self.checker_callback_tag = None
        self.check_command = checker
    def start(self):
        """Start this clients checker and timeout hooks"""
        # Schedule a new checker to be started an 'interval' from now,
        # and every interval from then on.
        self.checker_initiator_tag = gobject.timeout_add\
                                     (self._interval_milliseconds,
                                      self.start_checker)
        # Also start a new checker *right now*.
        self.start_checker()
        # Schedule a stop() when 'timeout' has passed
        self.stop_initiator_tag = gobject.timeout_add\
                                  (self._timeout_milliseconds,
                                   self.stop)
    def stop(self):
        """Stop this client.
        The possibility that this client might be restarted is left
        open, but not currently used."""
        if debug:
            sys.stderr.write(u"Stopping client %s\n" % self.name)
        self.secret = None
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
            if debug:
                sys.stderr.write(u"Checker for %(name)s succeeded\n"
                                 % vars(self))
            self.last_seen = now
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = gobject.timeout_add\
                                      (self._timeout_milliseconds,
                                       self.stop)
        elif debug:
            if not os.WIFEXITED(condition):
                sys.stderr.write(u"Checker for %(name)s crashed?\n"
                                 % vars(self))
            else:
                sys.stderr.write(u"Checker for %(name)s failed\n"
                                 % vars(self))
        self.checker = None
        self.checker_callback_tag = None
    def start_checker(self):
        """Start a new checker subprocess if one is not running.
        If a checker already exists, leave it running and do
        nothing."""
        if self.checker is None:
            if debug:
                sys.stderr.write(u"Starting checker for %s\n"
                                 % self.name)
            try:
                command = self.check_command % self.fqdn
            except TypeError:
                escaped_attrs = dict((key, re.escape(str(val)))
                                     for key, val in
                                     vars(self).iteritems())
                command = self.check_command % escaped_attrs
            try:
                self.checker = subprocess.\
                               Popen(command,
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


def peer_certificate(session):
    # If not an OpenPGP certificate...
    if gnutls.library.functions.gnutls_certificate_type_get\
            (session._c_object) \
           != gnutls.library.constants.GNUTLS_CRT_OPENPGP:
        # ...do the normal thing
        return session.peer_certificate
    list_size = ctypes.c_uint()
    cert_list = gnutls.library.functions.gnutls_certificate_get_peers\
        (session._c_object, ctypes.byref(list_size))
    if list_size.value == 0:
        return None
    cert = cert_list[0]
    return ctypes.string_at(cert.data, cert.size)


def fingerprint(openpgp):
    # New empty GnuTLS certificate
    crt = gnutls.library.types.gnutls_openpgp_crt_t()
    gnutls.library.functions.gnutls_openpgp_crt_init\
        (ctypes.byref(crt))
    # New GnuTLS "datum" with the OpenPGP public key
    datum = gnutls.library.types.gnutls_datum_t\
        (ctypes.cast(ctypes.c_char_p(openpgp),
                     ctypes.POINTER(ctypes.c_ubyte)),
         ctypes.c_uint(len(openpgp)))
    # Import the OpenPGP public key into the certificate
    ret = gnutls.library.functions.gnutls_openpgp_crt_import\
        (crt,
         ctypes.byref(datum),
         gnutls.library.constants.GNUTLS_OPENPGP_FMT_RAW)
    # New buffer for the fingerprint
    buffer = ctypes.create_string_buffer(20)
    buffer_length = ctypes.c_size_t()
    # Get the fingerprint from the certificate into the buffer
    gnutls.library.functions.gnutls_openpgp_crt_get_fingerprint\
        (crt, ctypes.byref(buffer), ctypes.byref(buffer_length))
    # Deinit the certificate
    gnutls.library.functions.gnutls_openpgp_crt_deinit(crt)
    # Convert the buffer to a Python bytestring
    fpr = ctypes.string_at(buffer, buffer_length.value)
    # Convert the bytestring to hexadecimal notation
    hex_fpr = u''.join(u"%02X" % ord(char) for char in fpr)
    return hex_fpr


class tcp_handler(SocketServer.BaseRequestHandler, object):
    """A TCP request handler class.
    Instantiated by IPv6_TCPServer for each request to handle it.
    Note: This will run in its own forked process."""
    
    def handle(self):
        if debug:
            sys.stderr.write(u"TCP request came\n")
            sys.stderr.write(u"Request: %s\n" % self.request)
            sys.stderr.write(u"Client Address: %s\n"
                             % unicode(self.client_address))
            sys.stderr.write(u"Server: %s\n" % self.server)
        session = gnutls.connection.ClientSession(self.request,
                                                  gnutls.connection.\
                                                  X509Credentials())
        
        #priority = ':'.join(("NONE", "+VERS-TLS1.1", "+AES-256-CBC",
        #                "+SHA1", "+COMP-NULL", "+CTYPE-OPENPGP",
        #                "+DHE-DSS"))
        priority = "SECURE256"
        
        gnutls.library.functions.gnutls_priority_set_direct\
            (session._c_object, priority, None);
        
        try:
            session.handshake()
        except gnutls.errors.GNUTLSError, error:
            if debug:
                sys.stderr.write(u"Handshake failed: %s\n" % error)
            # Do not run session.bye() here: the session is not
            # established.  Just abandon the request.
            return
        try:
            fpr = fingerprint(peer_certificate(session))
        except (TypeError, gnutls.errors.GNUTLSError), error:
            if debug:
                sys.stderr.write(u"Bad certificate: %s\n" % error)
            session.bye()
            return
        if debug:
            sys.stderr.write(u"Fingerprint: %s\n" % fpr)
        client = None
        for c in clients:
            if c.fingerprint == fpr:
                client = c
                break
        # Have to check if client.still_valid(), since it is possible
        # that the client timed out while establishing the GnuTLS
        # session.
        if (not client) or (not client.still_valid()):
            if debug:
                if client:
                    sys.stderr.write(u"Client %(name)s is invalid\n"
                                     % vars(client))
                else:
                    sys.stderr.write(u"Client not found for "
                                     u"fingerprint: %s\n" % fpr)
            session.bye()
            return
        sent_size = 0
        while sent_size < len(client.secret):
            sent = session.send(client.secret[sent_size:])
            if debug:
                sys.stderr.write(u"Sent: %d, remaining: %d\n"
                                 % (sent, len(client.secret)
                                    - (sent_size + sent)))
            sent_size += sent
        session.bye()


class IPv6_TCPServer(SocketServer.ForkingTCPServer, object):
    """IPv6 TCP server.  Accepts 'None' as address and/or port.
    Attributes:
        options:        Command line options
        clients:        Set() of Client objects
    """
    address_family = socket.AF_INET6
    def __init__(self, *args, **kwargs):
        if "options" in kwargs:
            self.options = kwargs["options"]
            del kwargs["options"]
        if "clients" in kwargs:
            self.clients = kwargs["clients"]
            del kwargs["clients"]
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
                    sys.stderr.write(u"Warning: No permission to" \
                                     u" bind to interface %s\n"
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
    if debug:
        sys.stderr.write(u"Adding service '%s' of type '%s' ...\n"
                         % (serviceName, serviceType))
    
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
        sys.stderr.write(u"WARNING: Server name collision\n")
        remove_service()
    elif state == avahi.SERVER_RUNNING:
        add_service()


def entry_group_state_changed(state, error):
    """From the Avahi server example code"""
    global serviceName, server, rename_count
    
    if debug:
        sys.stderr.write(u"state change: %i\n" % state)
    
    if state == avahi.ENTRY_GROUP_ESTABLISHED:
        if debug:
            sys.stderr.write(u"Service established.\n")
    elif state == avahi.ENTRY_GROUP_COLLISION:
        
        rename_count = rename_count - 1
        if rename_count > 0:
            name = server.GetAlternativeServiceName(name)
            sys.stderr.write(u"WARNING: Service name collision, "
                             u"changing name to '%s' ...\n" % name)
            remove_service()
            add_service()
            
        else:
            sys.stderr.write(u"ERROR: No suitable service name found "
                             u"after %i retries, exiting.\n"
                             % n_rename)
            main_loop.quit()
    elif state == avahi.ENTRY_GROUP_FAILURE:
        sys.stderr.write(u"Error in group state changed %s\n"
                         % unicode(error))
        main_loop.quit()
        return


def if_nametoindex(interface):
    """Call the C function if_nametoindex()"""
    try:
        libc = ctypes.cdll.LoadLibrary("libc.so.6")
        return libc.if_nametoindex(interface)
    except (OSError, AttributeError):
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
    parser.add_option("--debug", action="store_true", default=False,
                      help="Debug mode")
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
    
    # Parse config file
    defaults = { "checker": "sleep 1; fping -q -- %%(fqdn)s" }
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
    
    debug = options.debug
    
    clients = Set()
    def remove_from_clients(client):
        clients.remove(client)
        if not clients:
            if debug:
                sys.stderr.write(u"No clients left, exiting\n")
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
                                clients=clients)
    # Find out what random port we got
    servicePort = tcp_server.socket.getsockname()[1]
    if debug:
        sys.stderr.write(u"Now listening on port %d\n" % servicePort)
    
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
