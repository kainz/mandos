#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-
# 
# Mandos server - give out binary blobs to connecting clients.
# 
# This program is partly derived from an example program for an Avahi
# service publisher, downloaded from
# <http://avahi.org/wiki/PythonPublishExample>.  This includes the
# following functions: "add_service", "remove_service",
# "server_state_changed", "entry_group_state_changed", and some lines
# in "main".
# 
# Everything else is Copyright © 2007-2008 Teddy Hogeborn and Björn
# Påhlsson.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
# Contact the authors at <https://www.fukt.bsnet.se/~belorn/> and
# <https://www.fukt.bsnet.se/~teddy/>.
# 

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
import atexit
import stat
import logging
import logging.handlers

import dbus
import gobject
import avahi
from dbus.mainloop.glib import DBusGMainLoop
import ctypes

# Brief description of the operation of this program:
# 
# This server announces itself as a Zeroconf service.  Connecting
# clients use the TLS protocol, with the unusual quirk that this
# server program acts as a TLS "client" while the connecting clients
# acts as a TLS "server".  The clients (acting as a TLS "server") must
# supply an OpenPGP certificate, and the fingerprint of this
# certificate is used by this server to look up (in a list read from a
# file at start time) which binary blob to give the client.  No other
# authentication or authorization is done by this server.


logger = logging.Logger('mandos')
syslogger = logging.handlers.SysLogHandler\
            (facility = logging.handlers.SysLogHandler.LOG_DAEMON)
syslogger.setFormatter(logging.Formatter\
                        ('%(levelname)s: %(message)s'))
logger.addHandler(syslogger)
del syslogger

# This variable is used to optionally bind to a specified interface.
# It is a global variable to fit in with the other variables from the
# Avahi example code.
serviceInterface = avahi.IF_UNSPEC
# From the Avahi example code:
serviceName = None
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
    def __init__(self, name=None, stop_hook=None, fingerprint=None,
                 secret=None, secfile=None, fqdn=None, timeout=None,
                 interval=-1, checker=None):
        """Note: the 'checker' argument sets the 'checker_command'
        attribute and not the 'checker' attribute.."""
        self.name = name
        logger.debug(u"Creating client %r", self.name)
        # Uppercase and remove spaces from fingerprint
        # for later comparison purposes with return value of
        # the fingerprint() function
        self.fingerprint = fingerprint.upper().replace(u" ", u"")
        logger.debug(u"  Fingerprint: %s", self.fingerprint)
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
        self.timeout = string_to_delta(timeout)
        self.interval = string_to_delta(interval)
        self.stop_hook = stop_hook
        self.checker = None
        self.checker_initiator_tag = None
        self.stop_initiator_tag = None
        self.checker_callback_tag = None
        self.check_command = checker
    def start(self):
        """Start this client's checker and timeout hooks"""
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
        # If this client doesn't have a secret, it is already stopped.
        if self.secret:
            logger.debug(u"Stopping client %s", self.name)
            self.secret = None
        else:
            return False
        if hasattr(self, "stop_initiator_tag") \
               and self.stop_initiator_tag:
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = None
        if hasattr(self, "checker_initiator_tag") \
               and self.checker_initiator_tag:
            gobject.source_remove(self.checker_initiator_tag)
            self.checker_initiator_tag = None
        self.stop_checker()
        if self.stop_hook:
            self.stop_hook(self)
        # Do not run this again if called by a gobject.timeout_add
        return False
    def __del__(self):
        self.stop_hook = None
        self.stop()
    def checker_callback(self, pid, condition):
        """The checker has completed, so take appropriate actions."""
        now = datetime.datetime.now()
        self.checker_callback_tag = None
        self.checker = None
        if os.WIFEXITED(condition) \
               and (os.WEXITSTATUS(condition) == 0):
            logger.debug(u"Checker for %(name)s succeeded",
                         vars(self))
            self.last_seen = now
            gobject.source_remove(self.stop_initiator_tag)
            self.stop_initiator_tag = gobject.timeout_add\
                                      (self._timeout_milliseconds,
                                       self.stop)
        elif not os.WIFEXITED(condition):
            logger.warning(u"Checker for %(name)s crashed?",
                           vars(self))
        else:
            logger.debug(u"Checker for %(name)s failed",
                         vars(self))
    def start_checker(self):
        """Start a new checker subprocess if one is not running.
        If a checker already exists, leave it running and do
        nothing."""
        # The reason for not killing a running checker is that if we
        # did that, then if a checker (for some reason) started
        # running slowly and taking more than 'interval' time, the
        # client would inevitably timeout, since no checker would get
        # a chance to run to completion.  If we instead leave running
        # checkers alone, the checker would have to take more time
        # than 'timeout' for the client to be declared invalid, which
        # is as it should be.
        if self.checker is None:
            try:
                command = self.check_command % self.fqdn
            except TypeError:
                escaped_attrs = dict((key, re.escape(str(val)))
                                     for key, val in
                                     vars(self).iteritems())
                try:
                    command = self.check_command % escaped_attrs
                except TypeError, error:
                    logger.critical(u'Could not format string "%s":'
                                    u' %s', self.check_command, error)
                    return True # Try again later
            try:
                logger.debug(u"Starting checker %r for %s",
                             command, self.name)
                self.checker = subprocess.\
                               Popen(command,
                                     close_fds=True, shell=True,
                                     cwd="/")
                self.checker_callback_tag = gobject.child_watch_add\
                                            (self.checker.pid,
                                             self.checker_callback)
            except subprocess.OSError, error:
                logger.error(u"Failed to start subprocess: %s",
                             error)
        # Re-run this periodically if run by gobject.timeout_add
        return True
    def stop_checker(self):
        """Force the checker process, if any, to stop."""
        if self.checker_callback_tag:
            gobject.source_remove(self.checker_callback_tag)
            self.checker_callback_tag = None
        if not hasattr(self, "checker") or self.checker is None:
            return
        logger.debug("Stopping checker for %(name)s", vars(self))
        try:
            os.kill(self.checker.pid, signal.SIGTERM)
            #os.sleep(0.5)
            #if self.checker.poll() is None:
            #    os.kill(self.checker.pid, signal.SIGKILL)
        except OSError, error:
            if error.errno != errno.ESRCH:
                raise
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
    "Return the peer's OpenPGP certificate as a bytestring"
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
    "Convert an OpenPGP bytestring to a hexdigit fingerprint string"
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
        logger.debug(u"TCP connection from: %s",
                     unicode(self.client_address))
        session = gnutls.connection.ClientSession(self.request,
                                                  gnutls.connection.\
                                                  X509Credentials())
        
        #priority = ':'.join(("NONE", "+VERS-TLS1.1", "+AES-256-CBC",
        #                "+SHA1", "+COMP-NULL", "+CTYPE-OPENPGP",
        #                "+DHE-DSS"))
        priority = "NORMAL"
        if self.server.options.priority:
            priority = self.server.options.priority
        gnutls.library.functions.gnutls_priority_set_direct\
            (session._c_object, priority, None);
        
        try:
            session.handshake()
        except gnutls.errors.GNUTLSError, error:
            logger.debug(u"Handshake failed: %s", error)
            # Do not run session.bye() here: the session is not
            # established.  Just abandon the request.
            return
        try:
            fpr = fingerprint(peer_certificate(session))
        except (TypeError, gnutls.errors.GNUTLSError), error:
            logger.debug(u"Bad certificate: %s", error)
            session.bye()
            return
        logger.debug(u"Fingerprint: %s", fpr)
        client = None
        for c in self.server.clients:
            if c.fingerprint == fpr:
                client = c
                break
        # Have to check if client.still_valid(), since it is possible
        # that the client timed out while establishing the GnuTLS
        # session.
        if (not client) or (not client.still_valid()):
            if client:
                logger.debug(u"Client %(name)s is invalid",
                             vars(client))
            else:
                logger.debug(u"Client not found for fingerprint: %s",
                             fpr)
            session.bye()
            return
        sent_size = 0
        while sent_size < len(client.secret):
            sent = session.send(client.secret[sent_size:])
            logger.debug(u"Sent: %d, remaining: %d",
                         sent, len(client.secret)
                         - (sent_size + sent))
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
                    logger.warning(u"No permission to"
                                   u" bind to interface %s",
                                   self.options.interface)
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
    """Derived from the Avahi example code"""
    global group, serviceName, serviceType, servicePort, serviceTXT, \
           domain, host
    if group is None:
        group = dbus.Interface(
                bus.get_object( avahi.DBUS_NAME,
                                server.EntryGroupNew()),
                avahi.DBUS_INTERFACE_ENTRY_GROUP)
        group.connect_to_signal('StateChanged',
                                entry_group_state_changed)
    logger.debug(u"Adding service '%s' of type '%s' ...",
                 serviceName, serviceType)
    
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
    """From the Avahi example code"""
    global group
    
    if not group is None:
        group.Reset()


def server_state_changed(state):
    """Derived from the Avahi example code"""
    if state == avahi.SERVER_COLLISION:
        logger.warning(u"Server name collision")
        remove_service()
    elif state == avahi.SERVER_RUNNING:
        add_service()


def entry_group_state_changed(state, error):
    """Derived from the Avahi example code"""
    global serviceName, server, rename_count
    
    logger.debug(u"state change: %i", state)
    
    if state == avahi.ENTRY_GROUP_ESTABLISHED:
        logger.debug(u"Service established.")
    elif state == avahi.ENTRY_GROUP_COLLISION:
        
        rename_count = rename_count - 1
        if rename_count > 0:
            name = server.GetAlternativeServiceName(name)
            logger.warning(u"Service name collision, "
                           u"changing name to '%s' ...", name)
            remove_service()
            add_service()
            
        else:
            logger.error(u"No suitable service name found after %i"
                         u" retries, exiting.", n_rename)
            killme(1)
    elif state == avahi.ENTRY_GROUP_FAILURE:
        logger.error(u"Error in group state changed %s",
                     unicode(error))
        killme(1)


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


def daemon(nochdir, noclose):
    """See daemon(3).  Standard BSD Unix function.
    This should really exist as os.daemon, but it doesn't (yet)."""
    if os.fork():
        sys.exit()
    os.setsid()
    if not nochdir:
        os.chdir("/")
    if not noclose:
        # Close all standard open file descriptors
        null = os.open("/dev/null", os.O_NOCTTY | os.O_RDWR)
        if not stat.S_ISCHR(os.fstat(null).st_mode):
            raise OSError(errno.ENODEV,
                          "/dev/null not a character device")
        os.dup2(null, sys.stdin.fileno())
        os.dup2(null, sys.stdout.fileno())
        os.dup2(null, sys.stderr.fileno())
        if null > 2:
            os.close(null)


def killme(status = 0):
    logger.debug("Stopping server with exit status %d", status)
    exitstatus = status
    if main_loop_started:
        main_loop.quit()
    else:
        sys.exit(status)


def main():
    global exitstatus
    exitstatus = 0
    global main_loop_started
    main_loop_started = False
    
    parser = OptionParser()
    parser.add_option("-i", "--interface", type="string",
                      default=None, metavar="IF",
                      help="Bind to interface IF")
    parser.add_option("-a", "--address", type="string", default=None,
                      help="Address to listen for requests on")
    parser.add_option("-p", "--port", type="int", default=None,
                      help="Port number to receive requests on")
    parser.add_option("--check", action="store_true", default=False,
                      help="Run self-test")
    parser.add_option("--debug", action="store_true", default=False,
                      help="Debug mode")
    parser.add_option("--priority", type="string",
                      default="SECURE256",
                      help="GnuTLS priority string"
                      " (see GnuTLS documentation)")
    parser.add_option("--servicename", type="string",
                      default="Mandos", help="Zeroconf service name")
    (options, args) = parser.parse_args()
    
    if options.check:
        import doctest
        doctest.testmod()
        sys.exit()
    
    # Parse config file
    defaults = { "timeout": "1h",
                 "interval": "5m",
                 "checker": "fping -q -- %%(fqdn)s",
                 }
    client_config = ConfigParser.SafeConfigParser(defaults)
    #client_config.readfp(open("global.conf"), "global.conf")
    client_config.read("mandos-clients.conf")
    
    global serviceName
    serviceName = options.servicename;
    
    global main_loop
    global bus
    global server
    # From the Avahi example code
    DBusGMainLoop(set_as_default=True )
    main_loop = gobject.MainLoop()
    bus = dbus.SystemBus()
    server = dbus.Interface(
            bus.get_object( avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
            avahi.DBUS_INTERFACE_SERVER )
    # End of Avahi example code
    
    debug = options.debug
    
    if debug:
        console = logging.StreamHandler()
        # console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter\
                             ('%(levelname)s: %(message)s'))
        logger.addHandler(console)
        del console
    
    clients = Set()
    def remove_from_clients(client):
        clients.remove(client)
        if not clients:
            logger.debug(u"No clients left, exiting")
            killme()
    
    clients.update(Set(Client(name=section,
                              stop_hook = remove_from_clients,
                              **(dict(client_config\
                                      .items(section))))
                       for section in client_config.sections()))
    
    if not debug:
        daemon(False, False)
    
    def cleanup():
        "Cleanup function; run on exit"
        global group
        # From the Avahi example code
        if not group is None:
            group.Free()
            group = None
        # End of Avahi example code
        
        while clients:
            client = clients.pop()
            client.stop_hook = None
            client.stop()
    
    atexit.register(cleanup)
    
    if not debug:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, lambda signum, frame: killme())
    signal.signal(signal.SIGTERM, lambda signum, frame: killme())
    
    for client in clients:
        client.start()
    
    tcp_server = IPv6_TCPServer((options.address, options.port),
                                tcp_handler,
                                options=options,
                                clients=clients)
    # Find out what random port we got
    global servicePort
    servicePort = tcp_server.socket.getsockname()[1]
    logger.debug(u"Now listening on port %d", servicePort)
    
    if options.interface is not None:
        global serviceInterface
        serviceInterface = if_nametoindex(options.interface)
    
    # From the Avahi example code
    server.connect_to_signal("StateChanged", server_state_changed)
    try:
        server_state_changed(server.GetState())
    except dbus.exceptions.DBusException, error:
        logger.critical(u"DBusException: %s", error)
        killme(1)
    # End of Avahi example code
    
    gobject.io_add_watch(tcp_server.fileno(), gobject.IO_IN,
                         lambda *args, **kwargs:
                         tcp_server.handle_request(*args[2:],
                                                   **kwargs) or True)
    try:
        logger.debug("Starting main loop")
        main_loop_started = True
        main_loop.run()
    except KeyboardInterrupt:
        if debug:
            print
    
    sys.exit(exitstatus)

if __name__ == '__main__':
    main()
