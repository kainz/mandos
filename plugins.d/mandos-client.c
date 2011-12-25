/*  -*- coding: utf-8 -*- */
/*
 * Mandos-client - get and decrypt data from a Mandos server
 *
 * This program is partly derived from an example program for an Avahi
 * service browser, downloaded from
 * <http://avahi.org/browser/examples/core-browse-services.c>.  This
 * includes the following functions: "resolve_callback",
 * "browse_callback", and parts of "main".
 * 
 * Everything else is
 * Copyright © 2008-2011 Teddy Hogeborn
 * Copyright © 2008-2011 Björn Påhlsson
 * 
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 * 
 * Contact the authors at <mandos@recompile.se>.
 */

/* Needed by GPGME, specifically gpgme_data_seek() */
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY(), asprintf() */

#include <stdio.h>		/* fprintf(), stderr, fwrite(),
				   stdout, ferror(), remove() */
#include <stdint.h> 		/* uint16_t, uint32_t */
#include <stddef.h>		/* NULL, size_t, ssize_t */
#include <stdlib.h> 		/* free(), EXIT_SUCCESS, srand(),
				   strtof(), abort() */
#include <stdbool.h>		/* bool, false, true */
#include <string.h>		/* memset(), strcmp(), strlen(),
				   strerror(), asprintf(), strcpy() */
#include <sys/ioctl.h>		/* ioctl */
#include <sys/types.h>		/* socket(), inet_pton(), sockaddr,
				   sockaddr_in6, PF_INET6,
				   SOCK_STREAM, uid_t, gid_t, open(),
				   opendir(), DIR */
#include <sys/stat.h>		/* open(), S_ISREG */
#include <sys/socket.h>		/* socket(), struct sockaddr_in6,
				   inet_pton(), connect() */
#include <fcntl.h>		/* open() */
#include <dirent.h>		/* opendir(), struct dirent, readdir()
				 */
#include <inttypes.h>		/* PRIu16, PRIdMAX, intmax_t,
				   strtoimax() */
#include <assert.h>		/* assert() */
#include <errno.h>		/* perror(), errno,
				   program_invocation_short_name */
#include <time.h>		/* nanosleep(), time(), sleep() */
#include <net/if.h>		/* ioctl, ifreq, SIOCGIFFLAGS, IFF_UP,
				   SIOCSIFFLAGS, if_indextoname(),
				   if_nametoindex(), IF_NAMESIZE */
#include <netinet/in.h>		/* IN6_IS_ADDR_LINKLOCAL,
				   INET_ADDRSTRLEN, INET6_ADDRSTRLEN
				*/
#include <unistd.h>		/* close(), SEEK_SET, off_t, write(),
				   getuid(), getgid(), seteuid(),
				   setgid(), pause(), _exit() */
#include <arpa/inet.h>		/* inet_pton(), htons, inet_ntop() */
#include <iso646.h>		/* not, or, and */
#include <argp.h>		/* struct argp_option, error_t, struct
				   argp_state, struct argp,
				   argp_parse(), ARGP_KEY_ARG,
				   ARGP_KEY_END, ARGP_ERR_UNKNOWN */
#include <signal.h>		/* sigemptyset(), sigaddset(),
				   sigaction(), SIGTERM, sig_atomic_t,
				   raise() */
#include <sysexits.h>		/* EX_OSERR, EX_USAGE, EX_UNAVAILABLE,
				   EX_NOHOST, EX_IOERR, EX_PROTOCOL */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS(), WTERMSIG() */
#include <grp.h>		/* setgroups() */

#ifdef __linux__
#include <sys/klog.h> 		/* klogctl() */
#endif	/* __linux__ */

/* Avahi */
/* All Avahi types, constants and functions
 Avahi*, avahi_*,
 AVAHI_* */
#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/log.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

/* GnuTLS */
#include <gnutls/gnutls.h>	/* All GnuTLS types, constants and
				   functions:
				   gnutls_*
				   init_gnutls_session(),
				   GNUTLS_* */
#include <gnutls/openpgp.h>
			 /* gnutls_certificate_set_openpgp_key_file(),
			    GNUTLS_OPENPGP_FMT_BASE64 */

/* GPGME */
#include <gpgme.h> 		/* All GPGME types, constants and
				   functions:
				   gpgme_*
				   GPGME_PROTOCOL_OpenPGP,
				   GPG_ERR_NO_* */

#define BUFFER_SIZE 256

#define PATHDIR "/conf/conf.d/mandos"
#define SECKEY "seckey.txt"
#define PUBKEY "pubkey.txt"
#define HOOKDIR "/lib/mandos/network-hooks.d"

bool debug = false;
static const char mandos_protocol_version[] = "1";
const char *argp_program_version = "mandos-client " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";
static const char sys_class_net[] = "/sys/class/net";
char *connect_to = NULL;
const char *hookdir = HOOKDIR;

/* Doubly linked list that need to be circularly linked when used */
typedef struct server{
  const char *ip;
  uint16_t port;
  AvahiIfIndex if_index;
  int af;
  struct timespec last_seen;
  struct server *next;
  struct server *prev;
} server;

/* Used for passing in values through the Avahi callback functions */
typedef struct {
  AvahiSimplePoll *simple_poll;
  AvahiServer *server;
  gnutls_certificate_credentials_t cred;
  unsigned int dh_bits;
  gnutls_dh_params_t dh_params;
  const char *priority;
  gpgme_ctx_t ctx;
  server *current_server;
} mandos_context;

/* global context so signal handler can reach it*/
mandos_context mc = { .simple_poll = NULL, .server = NULL,
		      .dh_bits = 1024, .priority = "SECURE256"
		      ":!CTYPE-X.509:+CTYPE-OPENPGP",
		      .current_server = NULL };

sig_atomic_t quit_now = 0;
int signal_received = 0;

/* Function to use when printing errors */
void perror_plus(const char *print_text){
  int e = errno;
  fprintf(stderr, "Mandos plugin %s: ",
	  program_invocation_short_name);
  errno = e;
  perror(print_text);
}

__attribute__((format (gnu_printf, 2, 3)))
int fprintf_plus(FILE *stream, const char *format, ...){
  va_list ap;
  va_start (ap, format);
  
  TEMP_FAILURE_RETRY(fprintf(stream, "Mandos plugin %s: ",
			     program_invocation_short_name));
  return TEMP_FAILURE_RETRY(vfprintf(stream, format, ap));
}

/*
 * Make additional room in "buffer" for at least BUFFER_SIZE more
 * bytes. "buffer_capacity" is how much is currently allocated,
 * "buffer_length" is how much is already used.
 */
size_t incbuffer(char **buffer, size_t buffer_length,
		 size_t buffer_capacity){
  if(buffer_length + BUFFER_SIZE > buffer_capacity){
    *buffer = realloc(*buffer, buffer_capacity + BUFFER_SIZE);
    if(buffer == NULL){
      return 0;
    }
    buffer_capacity += BUFFER_SIZE;
  }
  return buffer_capacity;
}

/* Add server to set of servers to retry periodically */
bool add_server(const char *ip, uint16_t port, AvahiIfIndex if_index,
		int af){
  int ret;
  server *new_server = malloc(sizeof(server));
  if(new_server == NULL){
    perror_plus("malloc");
    return false;
  }
  *new_server = (server){ .ip = strdup(ip),
			  .port = port,
			  .if_index = if_index,
			  .af = af };
  if(new_server->ip == NULL){
    perror_plus("strdup");
    return false;
  }
  /* Special case of first server */
  if (mc.current_server == NULL){
    new_server->next = new_server;
    new_server->prev = new_server;
    mc.current_server = new_server;
  /* Place the new server last in the list */
  } else {
    new_server->next = mc.current_server;
    new_server->prev = mc.current_server->prev;
    new_server->prev->next = new_server;
    mc.current_server->prev = new_server;
  }
  ret = clock_gettime(CLOCK_MONOTONIC, &mc.current_server->last_seen);
  if(ret == -1){
    perror_plus("clock_gettime");
    return false;
  }
  return true;
}

/* 
 * Initialize GPGME.
 */
static bool init_gpgme(const char *seckey, const char *pubkey,
		       const char *tempdir){
  gpgme_error_t rc;
  gpgme_engine_info_t engine_info;
  
  
  /*
   * Helper function to insert pub and seckey to the engine keyring.
   */
  bool import_key(const char *filename){
    int ret;
    int fd;
    gpgme_data_t pgp_data;
    
    fd = (int)TEMP_FAILURE_RETRY(open(filename, O_RDONLY));
    if(fd == -1){
      perror_plus("open");
      return false;
    }
    
    rc = gpgme_data_new_from_fd(&pgp_data, fd);
    if(rc != GPG_ERR_NO_ERROR){
      fprintf_plus(stderr, "bad gpgme_data_new_from_fd: %s: %s\n",
		   gpgme_strsource(rc), gpgme_strerror(rc));
      return false;
    }
    
    rc = gpgme_op_import(mc.ctx, pgp_data);
    if(rc != GPG_ERR_NO_ERROR){
      fprintf_plus(stderr, "bad gpgme_op_import: %s: %s\n",
		   gpgme_strsource(rc), gpgme_strerror(rc));
      return false;
    }
    
    ret = (int)TEMP_FAILURE_RETRY(close(fd));
    if(ret == -1){
      perror_plus("close");
    }
    gpgme_data_release(pgp_data);
    return true;
  }
  
  if(debug){
    fprintf_plus(stderr, "Initializing GPGME\n");
  }
  
  /* Init GPGME */
  gpgme_check_version(NULL);
  rc = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "bad gpgme_engine_check_version: %s: %s\n",
		 gpgme_strsource(rc), gpgme_strerror(rc));
    return false;
  }
  
  /* Set GPGME home directory for the OpenPGP engine only */
  rc = gpgme_get_engine_info(&engine_info);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "bad gpgme_get_engine_info: %s: %s\n",
		 gpgme_strsource(rc), gpgme_strerror(rc));
    return false;
  }
  while(engine_info != NULL){
    if(engine_info->protocol == GPGME_PROTOCOL_OpenPGP){
      gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP,
			    engine_info->file_name, tempdir);
      break;
    }
    engine_info = engine_info->next;
  }
  if(engine_info == NULL){
    fprintf_plus(stderr, "Could not set GPGME home dir to %s\n",
		 tempdir);
    return false;
  }
  
  /* Create new GPGME "context" */
  rc = gpgme_new(&(mc.ctx));
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "Mandos plugin mandos-client: "
		 "bad gpgme_new: %s: %s\n", gpgme_strsource(rc),
		 gpgme_strerror(rc));
    return false;
  }
  
  if(not import_key(pubkey) or not import_key(seckey)){
    return false;
  }
  
  return true;
}

/* 
 * Decrypt OpenPGP data.
 * Returns -1 on error
 */
static ssize_t pgp_packet_decrypt(const char *cryptotext,
				  size_t crypto_size,
				  char **plaintext){
  gpgme_data_t dh_crypto, dh_plain;
  gpgme_error_t rc;
  ssize_t ret;
  size_t plaintext_capacity = 0;
  ssize_t plaintext_length = 0;
  
  if(debug){
    fprintf_plus(stderr, "Trying to decrypt OpenPGP data\n");
  }
  
  /* Create new GPGME data buffer from memory cryptotext */
  rc = gpgme_data_new_from_mem(&dh_crypto, cryptotext, crypto_size,
			       0);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "bad gpgme_data_new_from_mem: %s: %s\n",
		 gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  
  /* Create new empty GPGME data buffer for the plaintext */
  rc = gpgme_data_new(&dh_plain);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "Mandos plugin mandos-client: "
		 "bad gpgme_data_new: %s: %s\n",
		 gpgme_strsource(rc), gpgme_strerror(rc));
    gpgme_data_release(dh_crypto);
    return -1;
  }
  
  /* Decrypt data from the cryptotext data buffer to the plaintext
     data buffer */
  rc = gpgme_op_decrypt(mc.ctx, dh_crypto, dh_plain);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf_plus(stderr, "bad gpgme_op_decrypt: %s: %s\n",
		 gpgme_strsource(rc), gpgme_strerror(rc));
    plaintext_length = -1;
    if(debug){
      gpgme_decrypt_result_t result;
      result = gpgme_op_decrypt_result(mc.ctx);
      if(result == NULL){
	fprintf_plus(stderr, "gpgme_op_decrypt_result failed\n");
      } else {
	fprintf_plus(stderr, "Unsupported algorithm: %s\n",
		     result->unsupported_algorithm);
	fprintf_plus(stderr, "Wrong key usage: %u\n",
		     result->wrong_key_usage);
	if(result->file_name != NULL){
	  fprintf_plus(stderr, "File name: %s\n", result->file_name);
	}
	gpgme_recipient_t recipient;
	recipient = result->recipients;
	while(recipient != NULL){
	  fprintf_plus(stderr, "Public key algorithm: %s\n",
		       gpgme_pubkey_algo_name
		       (recipient->pubkey_algo));
	  fprintf_plus(stderr, "Key ID: %s\n", recipient->keyid);
	  fprintf_plus(stderr, "Secret key available: %s\n",
		       recipient->status == GPG_ERR_NO_SECKEY
		       ? "No" : "Yes");
	  recipient = recipient->next;
	}
      }
    }
    goto decrypt_end;
  }
  
  if(debug){
    fprintf_plus(stderr, "Decryption of OpenPGP data succeeded\n");
  }
  
  /* Seek back to the beginning of the GPGME plaintext data buffer */
  if(gpgme_data_seek(dh_plain, (off_t)0, SEEK_SET) == -1){
    perror_plus("gpgme_data_seek");
    plaintext_length = -1;
    goto decrypt_end;
  }
  
  *plaintext = NULL;
  while(true){
    plaintext_capacity = incbuffer(plaintext,
				   (size_t)plaintext_length,
				   plaintext_capacity);
    if(plaintext_capacity == 0){
      perror_plus("incbuffer");
      plaintext_length = -1;
      goto decrypt_end;
    }
    
    ret = gpgme_data_read(dh_plain, *plaintext + plaintext_length,
			  BUFFER_SIZE);
    /* Print the data, if any */
    if(ret == 0){
      /* EOF */
      break;
    }
    if(ret < 0){
      perror_plus("gpgme_data_read");
      plaintext_length = -1;
      goto decrypt_end;
    }
    plaintext_length += ret;
  }
  
  if(debug){
    fprintf_plus(stderr, "Decrypted password is: ");
    for(ssize_t i = 0; i < plaintext_length; i++){
      fprintf(stderr, "%02hhX ", (*plaintext)[i]);
    }
    fprintf(stderr, "\n");
  }
  
 decrypt_end:
  
  /* Delete the GPGME cryptotext data buffer */
  gpgme_data_release(dh_crypto);
  
  /* Delete the GPGME plaintext data buffer */
  gpgme_data_release(dh_plain);
  return plaintext_length;
}

static const char * safer_gnutls_strerror(int value){
  const char *ret = gnutls_strerror(value); /* Spurious warning from
					       -Wunreachable-code */
  if(ret == NULL)
    ret = "(unknown)";
  return ret;
}

/* GnuTLS log function callback */
static void debuggnutls(__attribute__((unused)) int level,
			const char* string){
  fprintf_plus(stderr, "GnuTLS: %s", string);
}

static int init_gnutls_global(const char *pubkeyfilename,
			      const char *seckeyfilename){
  int ret;
  
  if(debug){
    fprintf_plus(stderr, "Initializing GnuTLS\n");
  }
  
  ret = gnutls_global_init();
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr, "GnuTLS global_init: %s\n",
		 safer_gnutls_strerror(ret));
    return -1;
  }
  
  if(debug){
    /* "Use a log level over 10 to enable all debugging options."
     * - GnuTLS manual
     */
    gnutls_global_set_log_level(11);
    gnutls_global_set_log_function(debuggnutls);
  }
  
  /* OpenPGP credentials */
  ret = gnutls_certificate_allocate_credentials(&mc.cred);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr, "GnuTLS memory error: %s\n",
		 safer_gnutls_strerror(ret));
    gnutls_global_deinit();
    return -1;
  }
  
  if(debug){
    fprintf_plus(stderr, "Attempting to use OpenPGP public key %s and"
		 " secret key %s as GnuTLS credentials\n",
		 pubkeyfilename,
		 seckeyfilename);
  }
  
  ret = gnutls_certificate_set_openpgp_key_file
    (mc.cred, pubkeyfilename, seckeyfilename,
     GNUTLS_OPENPGP_FMT_BASE64);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr,
		 "Error[%d] while reading the OpenPGP key pair ('%s',"
		 " '%s')\n", ret, pubkeyfilename, seckeyfilename);
    fprintf_plus(stderr, "The GnuTLS error is: %s\n",
		 safer_gnutls_strerror(ret));
    goto globalfail;
  }
  
  /* GnuTLS server initialization */
  ret = gnutls_dh_params_init(&mc.dh_params);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr, "Error in GnuTLS DH parameter"
		 " initialization: %s\n",
		 safer_gnutls_strerror(ret));
    goto globalfail;
  }
  ret = gnutls_dh_params_generate2(mc.dh_params, mc.dh_bits);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr, "Error in GnuTLS prime generation: %s\n",
		 safer_gnutls_strerror(ret));
    goto globalfail;
  }
  
  gnutls_certificate_set_dh_params(mc.cred, mc.dh_params);
  
  return 0;
  
 globalfail:
  
  gnutls_certificate_free_credentials(mc.cred);
  gnutls_global_deinit();
  gnutls_dh_params_deinit(mc.dh_params);
  return -1;
}

static int init_gnutls_session(gnutls_session_t *session){
  int ret;
  /* GnuTLS session creation */
  do {
    ret = gnutls_init(session, GNUTLS_SERVER);
    if(quit_now){
      return -1;
    }
  } while(ret == GNUTLS_E_INTERRUPTED or ret == GNUTLS_E_AGAIN);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr,
		 "Error in GnuTLS session initialization: %s\n",
		 safer_gnutls_strerror(ret));
  }
  
  {
    const char *err;
    do {
      ret = gnutls_priority_set_direct(*session, mc.priority, &err);
      if(quit_now){
	gnutls_deinit(*session);
	return -1;
      }
    } while(ret == GNUTLS_E_INTERRUPTED or ret == GNUTLS_E_AGAIN);
    if(ret != GNUTLS_E_SUCCESS){
      fprintf_plus(stderr, "Syntax error at: %s\n", err);
      fprintf_plus(stderr, "GnuTLS error: %s\n",
		   safer_gnutls_strerror(ret));
      gnutls_deinit(*session);
      return -1;
    }
  }
  
  do {
    ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE,
				 mc.cred);
    if(quit_now){
      gnutls_deinit(*session);
      return -1;
    }
  } while(ret == GNUTLS_E_INTERRUPTED or ret == GNUTLS_E_AGAIN);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf_plus(stderr, "Error setting GnuTLS credentials: %s\n",
		 safer_gnutls_strerror(ret));
    gnutls_deinit(*session);
    return -1;
  }
  
  /* ignore client certificate if any. */
  gnutls_certificate_server_set_request(*session, GNUTLS_CERT_IGNORE);
  
  gnutls_dh_set_prime_bits(*session, mc.dh_bits);
  
  return 0;
}

/* Avahi log function callback */
static void empty_log(__attribute__((unused)) AvahiLogLevel level,
		      __attribute__((unused)) const char *txt){}

/* Called when a Mandos server is found */
static int start_mandos_communication(const char *ip, uint16_t port,
				      AvahiIfIndex if_index,
				      int af){
  int ret, tcp_sd = -1;
  ssize_t sret;
  union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  } to;
  char *buffer = NULL;
  char *decrypted_buffer = NULL;
  size_t buffer_length = 0;
  size_t buffer_capacity = 0;
  size_t written;
  int retval = -1;
  gnutls_session_t session;
  int pf;			/* Protocol family */
  
  errno = 0;
  
  if(quit_now){
    errno = EINTR;
    return -1;
  }
  
  switch(af){
  case AF_INET6:
    pf = PF_INET6;
    break;
  case AF_INET:
    pf = PF_INET;
    break;
  default:
    fprintf_plus(stderr, "Bad address family: %d\n", af);
    errno = EINVAL;
    return -1;
  }
  
  ret = init_gnutls_session(&session);
  if(ret != 0){
    return -1;
  }
  
  if(debug){
    fprintf_plus(stderr, "Setting up a TCP connection to %s, port %"
		 PRIu16 "\n", ip, port);
  }
  
  tcp_sd = socket(pf, SOCK_STREAM, 0);
  if(tcp_sd < 0){
    int e = errno;
    perror_plus("socket");
    errno = e;
    goto mandos_end;
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  memset(&to, 0, sizeof(to));
  if(af == AF_INET6){
    to.in6.sin6_family = (sa_family_t)af;
    ret = inet_pton(af, ip, &to.in6.sin6_addr);
  } else {			/* IPv4 */
    to.in.sin_family = (sa_family_t)af;
    ret = inet_pton(af, ip, &to.in.sin_addr);
  }
  if(ret < 0 ){
    int e = errno;
    perror_plus("inet_pton");
    errno = e;
    goto mandos_end;
  }
  if(ret == 0){
    int e = errno;
    fprintf_plus(stderr, "Bad address: %s\n", ip);
    errno = e;
    goto mandos_end;
  }
  if(af == AF_INET6){
    to.in6.sin6_port = htons(port); /* Spurious warnings from
				       -Wconversion and
				       -Wunreachable-code */
    
    if(IN6_IS_ADDR_LINKLOCAL /* Spurious warnings from */
       (&to.in6.sin6_addr)){ /* -Wstrict-aliasing=2 or lower and
				-Wunreachable-code*/
      if(if_index == AVAHI_IF_UNSPEC){
	fprintf_plus(stderr, "An IPv6 link-local address is"
		     " incomplete without a network interface\n");
	errno = EINVAL;
	goto mandos_end;
      }
      /* Set the network interface number as scope */
      to.in6.sin6_scope_id = (uint32_t)if_index;
    }
  } else {
    to.in.sin_port = htons(port); /* Spurious warnings from
				     -Wconversion and
				     -Wunreachable-code */
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  if(debug){
    if(af == AF_INET6 and if_index != AVAHI_IF_UNSPEC){
      char interface[IF_NAMESIZE];
      if(if_indextoname((unsigned int)if_index, interface) == NULL){
	perror_plus("if_indextoname");
      } else {
	fprintf_plus(stderr, "Connection to: %s%%%s, port %" PRIu16
		     "\n", ip, interface, port);
      }
    } else {
      fprintf_plus(stderr, "Connection to: %s, port %" PRIu16 "\n",
		   ip, port);
    }
    char addrstr[(INET_ADDRSTRLEN > INET6_ADDRSTRLEN) ?
		 INET_ADDRSTRLEN : INET6_ADDRSTRLEN] = "";
    const char *pcret;
    if(af == AF_INET6){
      pcret = inet_ntop(af, &(to.in6.sin6_addr), addrstr,
			sizeof(addrstr));
    } else {
      pcret = inet_ntop(af, &(to.in.sin_addr), addrstr,
			sizeof(addrstr));
    }
    if(pcret == NULL){
      perror_plus("inet_ntop");
    } else {
      if(strcmp(addrstr, ip) != 0){
	fprintf_plus(stderr, "Canonical address form: %s\n", addrstr);
      }
    }
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  if(af == AF_INET6){
    ret = connect(tcp_sd, &to.in6, sizeof(to));
  } else {
    ret = connect(tcp_sd, &to.in, sizeof(to)); /* IPv4 */
  }
  if(ret < 0){
    if ((errno != ECONNREFUSED and errno != ENETUNREACH) or debug){
      int e = errno;
      perror_plus("connect");
      errno = e;
    }
    goto mandos_end;
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  const char *out = mandos_protocol_version;
  written = 0;
  while(true){
    size_t out_size = strlen(out);
    ret = (int)TEMP_FAILURE_RETRY(write(tcp_sd, out + written,
					out_size - written));
    if(ret == -1){
      int e = errno;
      perror_plus("write");
      errno = e;
      goto mandos_end;
    }
    written += (size_t)ret;
    if(written < out_size){
      continue;
    } else {
      if(out == mandos_protocol_version){
	written = 0;
	out = "\r\n";
      } else {
	break;
      }
    }
  
    if(quit_now){
      errno = EINTR;
      goto mandos_end;
    }
  }
  
  if(debug){
    fprintf_plus(stderr, "Establishing TLS session with %s\n", ip);
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  /* Spurious warning from -Wint-to-pointer-cast */
  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) tcp_sd);
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  do {
    ret = gnutls_handshake(session);
    if(quit_now){
      errno = EINTR;
      goto mandos_end;
    }
  } while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
  
  if(ret != GNUTLS_E_SUCCESS){
    if(debug){
      fprintf_plus(stderr, "*** GnuTLS Handshake failed ***\n");
      gnutls_perror(ret);
    }
    errno = EPROTO;
    goto mandos_end;
  }
  
  /* Read OpenPGP packet that contains the wanted password */
  
  if(debug){
    fprintf_plus(stderr, "Retrieving OpenPGP encrypted password from"
		 " %s\n", ip);
  }
  
  while(true){
    
    if(quit_now){
      errno = EINTR;
      goto mandos_end;
    }
    
    buffer_capacity = incbuffer(&buffer, buffer_length,
				buffer_capacity);
    if(buffer_capacity == 0){
      int e = errno;
      perror_plus("incbuffer");
      errno = e;
      goto mandos_end;
    }
    
    if(quit_now){
      errno = EINTR;
      goto mandos_end;
    }
    
    sret = gnutls_record_recv(session, buffer+buffer_length,
			      BUFFER_SIZE);
    if(sret == 0){
      break;
    }
    if(sret < 0){
      switch(sret){
      case GNUTLS_E_INTERRUPTED:
      case GNUTLS_E_AGAIN:
	break;
      case GNUTLS_E_REHANDSHAKE:
	do {
	  ret = gnutls_handshake(session);
	  
	  if(quit_now){
	    errno = EINTR;
	    goto mandos_end;
	  }
	} while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
	if(ret < 0){
	  fprintf_plus(stderr, "*** GnuTLS Re-handshake failed "
		       "***\n");
	  gnutls_perror(ret);
	  errno = EPROTO;
	  goto mandos_end;
	}
	break;
      default:
	fprintf_plus(stderr, "Unknown error while reading data from"
		     " encrypted session with Mandos server\n");
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	errno = EIO;
	goto mandos_end;
      }
    } else {
      buffer_length += (size_t) sret;
    }
  }
  
  if(debug){
    fprintf_plus(stderr, "Closing TLS session\n");
  }
  
  if(quit_now){
    errno = EINTR;
    goto mandos_end;
  }
  
  do {
    ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
    if(quit_now){
      errno = EINTR;
      goto mandos_end;
    }
  } while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
  
  if(buffer_length > 0){
    ssize_t decrypted_buffer_size;
    decrypted_buffer_size = pgp_packet_decrypt(buffer, buffer_length,
					       &decrypted_buffer);
    if(decrypted_buffer_size >= 0){
      
      written = 0;
      while(written < (size_t) decrypted_buffer_size){
	if(quit_now){
	  errno = EINTR;
	  goto mandos_end;
	}
	
	ret = (int)fwrite(decrypted_buffer + written, 1,
			  (size_t)decrypted_buffer_size - written,
			  stdout);
	if(ret == 0 and ferror(stdout)){
	  int e = errno;
	  if(debug){
	    fprintf_plus(stderr, "Error writing encrypted data: %s\n",
			 strerror(errno));
	  }
	  errno = e;
	  goto mandos_end;
	}
	written += (size_t)ret;
      }
      retval = 0;
    }
  }
  
  /* Shutdown procedure */
  
 mandos_end:
  {
    int e = errno;
    free(decrypted_buffer);
    free(buffer);
    if(tcp_sd >= 0){
      ret = (int)TEMP_FAILURE_RETRY(close(tcp_sd));
    }
    if(ret == -1){
      if(e == 0){
	e = errno;
      }
      perror_plus("close");
    }
    gnutls_deinit(session);
    errno = e;
    if(quit_now){
      errno = EINTR;
      retval = -1;
    }
  }
  return retval;
}

static void resolve_callback(AvahiSServiceResolver *r,
			     AvahiIfIndex interface,
			     AvahiProtocol proto,
			     AvahiResolverEvent event,
			     const char *name,
			     const char *type,
			     const char *domain,
			     const char *host_name,
			     const AvahiAddress *address,
			     uint16_t port,
			     AVAHI_GCC_UNUSED AvahiStringList *txt,
			     AVAHI_GCC_UNUSED AvahiLookupResultFlags
			     flags,
			     AVAHI_GCC_UNUSED void* userdata){
  assert(r);
  
  /* Called whenever a service has been resolved successfully or
     timed out */
  
  if(quit_now){
    return;
  }
  
  switch(event){
  default:
  case AVAHI_RESOLVER_FAILURE:
    fprintf_plus(stderr, "(Avahi Resolver) Failed to resolve service "
		 "'%s' of type '%s' in domain '%s': %s\n", name, type,
		 domain,
		 avahi_strerror(avahi_server_errno(mc.server)));
    break;
    
  case AVAHI_RESOLVER_FOUND:
    {
      char ip[AVAHI_ADDRESS_STR_MAX];
      avahi_address_snprint(ip, sizeof(ip), address);
      if(debug){
	fprintf_plus(stderr, "Mandos server \"%s\" found on %s (%s, %"
		     PRIdMAX ") on port %" PRIu16 "\n", name,
		     host_name, ip, (intmax_t)interface, port);
      }
      int ret = start_mandos_communication(ip, port, interface,
					   avahi_proto_to_af(proto));
      if(ret == 0){
	avahi_simple_poll_quit(mc.simple_poll);
      } else {
	if(not add_server(ip, port, interface,
			  avahi_proto_to_af(proto))){
	  fprintf_plus(stderr, "Failed to add server \"%s\" to server"
		       " list\n", name);
	}
      }
    }
  }
  avahi_s_service_resolver_free(r);
}

static void browse_callback(AvahiSServiceBrowser *b,
			    AvahiIfIndex interface,
			    AvahiProtocol protocol,
			    AvahiBrowserEvent event,
			    const char *name,
			    const char *type,
			    const char *domain,
			    AVAHI_GCC_UNUSED AvahiLookupResultFlags
			    flags,
			    AVAHI_GCC_UNUSED void* userdata){
  assert(b);
  
  /* Called whenever a new services becomes available on the LAN or
     is removed from the LAN */
  
  if(quit_now){
    return;
  }
  
  switch(event){
  default:
  case AVAHI_BROWSER_FAILURE:
    
    fprintf_plus(stderr, "(Avahi browser) %s\n",
		 avahi_strerror(avahi_server_errno(mc.server)));
    avahi_simple_poll_quit(mc.simple_poll);
    return;
    
  case AVAHI_BROWSER_NEW:
    /* We ignore the returned Avahi resolver object. In the callback
       function we free it. If the Avahi server is terminated before
       the callback function is called the Avahi server will free the
       resolver for us. */
    
    if(avahi_s_service_resolver_new(mc.server, interface, protocol,
				    name, type, domain, protocol, 0,
				    resolve_callback, NULL) == NULL)
      fprintf_plus(stderr, "Avahi: Failed to resolve service '%s':"
		   " %s\n", name,
		   avahi_strerror(avahi_server_errno(mc.server)));
    break;
    
  case AVAHI_BROWSER_REMOVE:
    break;
    
  case AVAHI_BROWSER_ALL_FOR_NOW:
  case AVAHI_BROWSER_CACHE_EXHAUSTED:
    if(debug){
      fprintf_plus(stderr, "No Mandos server found, still"
		   " searching...\n");
    }
    break;
  }
}

/* Signal handler that stops main loop after SIGTERM */
static void handle_sigterm(int sig){
  if(quit_now){
    return;
  }
  quit_now = 1;
  signal_received = sig;
  int old_errno = errno;
  /* set main loop to exit */
  if(mc.simple_poll != NULL){
    avahi_simple_poll_quit(mc.simple_poll);
  }
  errno = old_errno;
}

bool get_flags(const char *ifname, struct ifreq *ifr){
  int ret;
  
  int s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
  if(s < 0){
    perror_plus("socket");
    return false;
  }
  strcpy(ifr->ifr_name, ifname);
  ret = ioctl(s, SIOCGIFFLAGS, ifr);
  if(ret == -1){
    if(debug){
      perror_plus("ioctl SIOCGIFFLAGS");
    }
    return false;
  }
  return true;
}

bool good_flags(const char *ifname, const struct ifreq *ifr){
  
  /* Reject the loopback device */
  if(ifr->ifr_flags & IFF_LOOPBACK){
    if(debug){
      fprintf_plus(stderr, "Rejecting loopback interface \"%s\"\n",
		   ifname);
    }
    return false;
  }
  /* Accept point-to-point devices only if connect_to is specified */
  if(connect_to != NULL and (ifr->ifr_flags & IFF_POINTOPOINT)){
    if(debug){
      fprintf_plus(stderr, "Accepting point-to-point interface"
		   " \"%s\"\n", ifname);
    }
    return true;
  }
  /* Otherwise, reject non-broadcast-capable devices */
  if(not (ifr->ifr_flags & IFF_BROADCAST)){
    if(debug){
      fprintf_plus(stderr, "Rejecting non-broadcast interface"
		   " \"%s\"\n", ifname);
    }
    return false;
  }
  /* Reject non-ARP interfaces (including dummy interfaces) */
  if(ifr->ifr_flags & IFF_NOARP){
    if(debug){
      fprintf_plus(stderr, "Rejecting non-ARP interface \"%s\"\n",
		   ifname);
    }
    return false;
  }
  
  /* Accept this device */
  if(debug){
    fprintf_plus(stderr, "Interface \"%s\" is good\n", ifname);
  }
  return true;
}

/* 
 * This function determines if a directory entry in /sys/class/net
 * corresponds to an acceptable network device.
 * (This function is passed to scandir(3) as a filter function.)
 */
int good_interface(const struct dirent *if_entry){
  if(if_entry->d_name[0] == '.'){
    return 0;
  }
  
  struct ifreq ifr;
  if(not get_flags(if_entry->d_name, &ifr)){
    if(debug){
      fprintf_plus(stderr, "Failed to get flags for interface "
		   "\"%s\"\n", if_entry->d_name);
    }
    return 0;
  }
  
  if(not good_flags(if_entry->d_name, &ifr)){
    return 0;
  }
  return 1;
}

/* 
 * This function determines if a directory entry in /sys/class/net
 * corresponds to an acceptable network device which is up.
 * (This function is passed to scandir(3) as a filter function.)
 */
int up_interface(const struct dirent *if_entry){
  if(if_entry->d_name[0] == '.'){
    return 0;
  }
  
  struct ifreq ifr;
  if(not get_flags(if_entry->d_name, &ifr)){
    if(debug){
      fprintf_plus(stderr, "Failed to get flags for interface "
		   "\"%s\"\n", if_entry->d_name);
    }
    return 0;
  }
  
  /* Reject down interfaces */
  if(not (ifr.ifr_flags & IFF_UP)){
    if(debug){
      fprintf_plus(stderr, "Rejecting down interface \"%s\"\n",
		   if_entry->d_name);
    }
    return 0;
  }
  
  /* Reject non-running interfaces */
  if(not (ifr.ifr_flags & IFF_RUNNING)){
    if(debug){
      fprintf_plus(stderr, "Rejecting non-running interface \"%s\"\n",
		   if_entry->d_name);
    }
    return 0;
  }
  
  if(not good_flags(if_entry->d_name, &ifr)){
    return 0;
  }
  return 1;
}

int notdotentries(const struct dirent *direntry){
  /* Skip "." and ".." */
  if(direntry->d_name[0] == '.'
     and (direntry->d_name[1] == '\0'
	  or (direntry->d_name[1] == '.'
	      and direntry->d_name[2] == '\0'))){
    return 0;
  }
  return 1;
}

/* Is this directory entry a runnable program? */
int runnable_hook(const struct dirent *direntry){
  int ret;
  size_t sret;
  struct stat st;
  
  if((direntry->d_name)[0] == '\0'){
    /* Empty name? */
    return 0;
  }
  
  sret = strspn(direntry->d_name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		"_-");
  if((direntry->d_name)[sret] != '\0'){
    /* Contains non-allowed characters */
    if(debug){
      fprintf_plus(stderr, "Ignoring hook \"%s\" with bad name\n",
		   direntry->d_name);
    }
    return 0;
  }
  
  char *fullname = NULL;
  ret = asprintf(&fullname, "%s/%s", hookdir, direntry->d_name);
  if(ret < 0){
    perror_plus("asprintf");
    return 0;
  }
  
  ret = stat(fullname, &st);
  if(ret == -1){
    if(debug){
      perror_plus("Could not stat hook");
    }
    return 0;
  }
  if(not (S_ISREG(st.st_mode))){
    /* Not a regular file */
    if(debug){
      fprintf_plus(stderr, "Ignoring hook \"%s\" - not a file\n",
		   direntry->d_name);
    }
    return 0;
  }
  if(not (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))){
    /* Not executable */
    if(debug){
      fprintf_plus(stderr, "Ignoring hook \"%s\" - not executable\n",
		   direntry->d_name);
    }
    return 0;
  }
  if(debug){
    fprintf_plus(stderr, "Hook \"%s\" is acceptable\n",
		 direntry->d_name);
  }
  return 1;
}

int avahi_loop_with_timeout(AvahiSimplePoll *s, int retry_interval){
  int ret;
  struct timespec now;
  struct timespec waited_time;
  intmax_t block_time;
  
  while(true){
    if(mc.current_server == NULL){
      if (debug){
	fprintf_plus(stderr, "Wait until first server is found."
		     " No timeout!\n");
      }
      ret = avahi_simple_poll_iterate(s, -1);
    } else {
      if (debug){
	fprintf_plus(stderr, "Check current_server if we should run"
		     " it, or wait\n");
      }
      /* the current time */
      ret = clock_gettime(CLOCK_MONOTONIC, &now);
      if(ret == -1){
	perror_plus("clock_gettime");
	return -1;
      }
      /* Calculating in ms how long time between now and server
	 who we visted longest time ago. Now - last seen.  */
      waited_time.tv_sec = (now.tv_sec
			    - mc.current_server->last_seen.tv_sec);
      waited_time.tv_nsec = (now.tv_nsec
			     - mc.current_server->last_seen.tv_nsec);
      /* total time is 10s/10,000ms.
	 Converting to s from ms by dividing by 1,000,
	 and ns to ms by dividing by 1,000,000. */
      block_time = ((retry_interval
		     - ((intmax_t)waited_time.tv_sec * 1000))
		    - ((intmax_t)waited_time.tv_nsec / 1000000));
      
      if (debug){
	fprintf_plus(stderr, "Blocking for %" PRIdMAX " ms\n",
		     block_time);
      }
      
      if(block_time <= 0){
	ret = start_mandos_communication(mc.current_server->ip,
					 mc.current_server->port,
					 mc.current_server->if_index,
					 mc.current_server->af);
	if(ret == 0){
	  avahi_simple_poll_quit(mc.simple_poll);
	  return 0;
	}
	ret = clock_gettime(CLOCK_MONOTONIC,
			    &mc.current_server->last_seen);
	if(ret == -1){
	  perror_plus("clock_gettime");
	  return -1;
	}
	mc.current_server = mc.current_server->next;
	block_time = 0; 	/* Call avahi to find new Mandos
				   servers, but don't block */
      }
      
      ret = avahi_simple_poll_iterate(s, (int)block_time);
    }
    if(ret != 0){
      if (ret > 0 or errno != EINTR){
	return (ret != 1) ? ret : 0;
      }
    }
  }
}

bool run_network_hooks(const char *mode, const char *interface,
		       const float delay){
  struct dirent **direntries;
  struct dirent *direntry;
  int ret;
  int numhooks = scandir(hookdir, &direntries, runnable_hook,
			 alphasort);
  if(numhooks == -1){
    perror_plus("scandir");
  } else {
    int devnull = open("/dev/null", O_RDONLY);
    for(int i = 0; i < numhooks; i++){
      direntry = direntries[i];
      char *fullname = NULL;
      ret = asprintf(&fullname, "%s/%s", hookdir, direntry->d_name);
      if(ret < 0){
	perror_plus("asprintf");
	continue;
      }
      if(debug){
	fprintf_plus(stderr, "Running network hook \"%s\"\n",
		     direntry->d_name);
      }
      pid_t hook_pid = fork();
      if(hook_pid == 0){
	/* Child */
	/* Raise privileges */
	errno = 0;
	ret = seteuid(0);
	if(ret == -1){
	  perror_plus("seteuid");
	}
	/* Raise privileges even more */
	errno = 0;
	ret = setuid(0);
	if(ret == -1){
	  perror_plus("setuid");
	}
	/* Set group */
	errno = 0;
	ret = setgid(0);
	if(ret == -1){
	  perror_plus("setgid");
	}
	/* Reset supplementary groups */
	errno = 0;
	ret = setgroups(0, NULL);
	if(ret == -1){
	  perror_plus("setgroups");
	}
	dup2(devnull, STDIN_FILENO);
	close(devnull);
	dup2(STDERR_FILENO, STDOUT_FILENO);
	ret = setenv("MANDOSNETHOOKDIR", hookdir, 1);
	if(ret == -1){
	  perror_plus("setenv");
	  _exit(EX_OSERR);
	}
	ret = setenv("DEVICE", interface, 1);
	if(ret == -1){
	  perror_plus("setenv");
	  _exit(EX_OSERR);
	}
	ret = setenv("VERBOSE", debug ? "1" : "0", 1);
	if(ret == -1){
	  perror_plus("setenv");
	  _exit(EX_OSERR);
	}
	ret = setenv("MODE", mode, 1);
	if(ret == -1){
	  perror_plus("setenv");
	  _exit(EX_OSERR);
	}
	char *delaystring;
	ret = asprintf(&delaystring, "%f", delay);
	if(ret == -1){
	  perror_plus("asprintf");
	  _exit(EX_OSERR);
	}
	ret = setenv("DELAY", delaystring, 1);
	if(ret == -1){
	  free(delaystring);
	  perror_plus("setenv");
	  _exit(EX_OSERR);
	}
	free(delaystring);
	if(execl(fullname, direntry->d_name, mode, NULL) == -1){
	  perror_plus("execl");
	  _exit(EXIT_FAILURE);
	}
      } else {
	int status;
	if(TEMP_FAILURE_RETRY(waitpid(hook_pid, &status, 0)) == -1){
	  perror_plus("waitpid");
	  free(fullname);
	  continue;
	}
	if(WIFEXITED(status)){
	  if(WEXITSTATUS(status) != 0){
	    fprintf_plus(stderr, "Warning: network hook \"%s\" exited"
			 " with status %d\n", direntry->d_name,
			 WEXITSTATUS(status));
	    free(fullname);
	    continue;
	  }
	} else if(WIFSIGNALED(status)){
	  fprintf_plus(stderr, "Warning: network hook \"%s\" died by"
		       " signal %d\n", direntry->d_name,
		       WTERMSIG(status));
	  free(fullname);
	  continue;
	} else {
	  fprintf_plus(stderr, "Warning: network hook \"%s\""
		       " crashed\n", direntry->d_name);
	  free(fullname);
	  continue;
	}
      }
      free(fullname);
      if(debug){
	fprintf_plus(stderr, "Network hook \"%s\" ran successfully\n",
		     direntry->d_name);
      }
    }
    close(devnull);
  }
  return true;
}

int main(int argc, char *argv[]){
  AvahiSServiceBrowser *sb = NULL;
  int error;
  int ret;
  intmax_t tmpmax;
  char *tmp;
  int exitcode = EXIT_SUCCESS;
  const char *interface = "";
  struct ifreq network;
  int sd = -1;
  bool take_down_interface = false;
  uid_t uid;
  gid_t gid;
  char tempdir[] = "/tmp/mandosXXXXXX";
  bool tempdir_created = false;
  AvahiIfIndex if_index = AVAHI_IF_UNSPEC;
  const char *seckey = PATHDIR "/" SECKEY;
  const char *pubkey = PATHDIR "/" PUBKEY;
  
  bool gnutls_initialized = false;
  bool gpgme_initialized = false;
  float delay = 2.5f;
  double retry_interval = 10; /* 10s between trying a server and
				 retrying the same server again */
  
  struct sigaction old_sigterm_action = { .sa_handler = SIG_DFL };
  struct sigaction sigterm_action = { .sa_handler = handle_sigterm };
  
  uid = getuid();
  gid = getgid();
  
  /* Lower any group privileges we might have, just to be safe */
  errno = 0;
  ret = setgid(gid);
  if(ret == -1){
    perror_plus("setgid");
  }
  
  /* Lower user privileges (temporarily) */
  errno = 0;
  ret = seteuid(uid);
  if(ret == -1){
    perror_plus("seteuid");
  }
  
  if(quit_now){
    goto end;
  }
  
  {
    struct argp_option options[] = {
      { .name = "debug", .key = 128,
	.doc = "Debug mode", .group = 3 },
      { .name = "connect", .key = 'c',
	.arg = "ADDRESS:PORT",
	.doc = "Connect directly to a specific Mandos server",
	.group = 1 },
      { .name = "interface", .key = 'i',
	.arg = "NAME",
	.doc = "Network interface that will be used to search for"
	" Mandos servers",
	.group = 1 },
      { .name = "seckey", .key = 's',
	.arg = "FILE",
	.doc = "OpenPGP secret key file base name",
	.group = 1 },
      { .name = "pubkey", .key = 'p',
	.arg = "FILE",
	.doc = "OpenPGP public key file base name",
	.group = 2 },
      { .name = "dh-bits", .key = 129,
	.arg = "BITS",
	.doc = "Bit length of the prime number used in the"
	" Diffie-Hellman key exchange",
	.group = 2 },
      { .name = "priority", .key = 130,
	.arg = "STRING",
	.doc = "GnuTLS priority string for the TLS handshake",
	.group = 1 },
      { .name = "delay", .key = 131,
	.arg = "SECONDS",
	.doc = "Maximum delay to wait for interface startup",
	.group = 2 },
      { .name = "retry", .key = 132,
	.arg = "SECONDS",
	.doc = "Retry interval used when denied by the mandos server",
	.group = 2 },
      { .name = "network-hook-dir", .key = 133,
	.arg = "DIR",
	.doc = "Directory where network hooks are located",
	.group = 2 },
      /*
       * These reproduce what we would get without ARGP_NO_HELP
       */
      { .name = "help", .key = '?',
	.doc = "Give this help list", .group = -1 },
      { .name = "usage", .key = -3,
	.doc = "Give a short usage message", .group = -1 },
      { .name = "version", .key = 'V',
	.doc = "Print program version", .group = -1 },
      { .name = NULL }
    };
    
    error_t parse_opt(int key, char *arg,
		      struct argp_state *state){
      errno = 0;
      switch(key){
      case 128:			/* --debug */
	debug = true;
	break;
      case 'c':			/* --connect */
	connect_to = arg;
	break;
      case 'i':			/* --interface */
	interface = arg;
	break;
      case 's':			/* --seckey */
	seckey = arg;
	break;
      case 'p':			/* --pubkey */
	pubkey = arg;
	break;
      case 129:			/* --dh-bits */
	errno = 0;
	tmpmax = strtoimax(arg, &tmp, 10);
	if(errno != 0 or tmp == arg or *tmp != '\0'
	   or tmpmax != (typeof(mc.dh_bits))tmpmax){
	  argp_error(state, "Bad number of DH bits");
	}
	mc.dh_bits = (typeof(mc.dh_bits))tmpmax;
	break;
      case 130:			/* --priority */
	mc.priority = arg;
	break;
      case 131:			/* --delay */
	errno = 0;
	delay = strtof(arg, &tmp);
	if(errno != 0 or tmp == arg or *tmp != '\0'){
	  argp_error(state, "Bad delay");
	}
      case 132:			/* --retry */
	errno = 0;
	retry_interval = strtod(arg, &tmp);
	if(errno != 0 or tmp == arg or *tmp != '\0'
	   or (retry_interval * 1000) > INT_MAX
	   or retry_interval < 0){
	  argp_error(state, "Bad retry interval");
	}
	break;
      case 133:			/* --network-hook-dir */
	hookdir = arg;
	break;
	/*
	 * These reproduce what we would get without ARGP_NO_HELP
	 */
      case '?':			/* --help */
	argp_state_help(state, state->out_stream,
			(ARGP_HELP_STD_HELP | ARGP_HELP_EXIT_ERR)
			& ~(unsigned int)ARGP_HELP_EXIT_OK);
      case -3:			/* --usage */
	argp_state_help(state, state->out_stream,
			ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR);
      case 'V':			/* --version */
	fprintf_plus(state->out_stream, "%s\n", argp_program_version);
	exit(argp_err_exit_status);
	break;
      default:
	return ARGP_ERR_UNKNOWN;
      }
      return errno;
    }
    
    struct argp argp = { .options = options, .parser = parse_opt,
			 .args_doc = "",
			 .doc = "Mandos client -- Get and decrypt"
			 " passwords from a Mandos server" };
    ret = argp_parse(&argp, argc, argv,
		     ARGP_IN_ORDER | ARGP_NO_HELP, 0, NULL);
    switch(ret){
    case 0:
      break;
    case ENOMEM:
    default:
      errno = ret;
      perror_plus("argp_parse");
      exitcode = EX_OSERR;
      goto end;
    case EINVAL:
      exitcode = EX_USAGE;
      goto end;
    }
  }
    
  {
    /* Work around Debian bug #633582:
       <http://bugs.debian.org/633582> */
    
    /* Re-raise priviliges */
    errno = 0;
    ret = seteuid(0);
    if(ret == -1){
      perror_plus("seteuid");
    } else {
      struct stat st;
      
      if(strcmp(seckey, PATHDIR "/" SECKEY) == 0){
	int seckey_fd = open(seckey, O_RDONLY);
	if(seckey_fd == -1){
	  perror_plus("open");
	} else {
	  ret = (int)TEMP_FAILURE_RETRY(fstat(seckey_fd, &st));
	  if(ret == -1){
	    perror_plus("fstat");
	  } else {
	    if(S_ISREG(st.st_mode)
	       and st.st_uid == 0 and st.st_gid == 0){
	      ret = fchown(seckey_fd, uid, gid);
	      if(ret == -1){
		perror_plus("fchown");
	      }
	    }
	  }
	  TEMP_FAILURE_RETRY(close(seckey_fd));
	}
      }
    
      if(strcmp(pubkey, PATHDIR "/" PUBKEY) == 0){
	int pubkey_fd = open(pubkey, O_RDONLY);
	if(pubkey_fd == -1){
	  perror_plus("open");
	} else {
	  ret = (int)TEMP_FAILURE_RETRY(fstat(pubkey_fd, &st));
	  if(ret == -1){
	    perror_plus("fstat");
	  } else {
	    if(S_ISREG(st.st_mode)
	       and st.st_uid == 0 and st.st_gid == 0){
	      ret = fchown(pubkey_fd, uid, gid);
	      if(ret == -1){
		perror_plus("fchown");
	      }
	    }
	  }
	  TEMP_FAILURE_RETRY(close(pubkey_fd));
	}
      }
    
      /* Lower privileges */
      errno = 0;
      ret = seteuid(uid);
      if(ret == -1){
	perror_plus("seteuid");
      }
    }
  }
  
  /* Run network hooks */
  if(not run_network_hooks("start", interface, delay)){
    goto end;
  }
  
  if(not debug){
    avahi_set_log_function(empty_log);
  }
  
  if(interface[0] == '\0'){
    struct dirent **direntries;
    /* First look for interfaces that are up */
    ret = scandir(sys_class_net, &direntries, up_interface,
		  alphasort);
    if(ret == 0){
      /* No up interfaces, look for any good interfaces */
      free(direntries);
      ret = scandir(sys_class_net, &direntries, good_interface,
		    alphasort);
    }
    if(ret >= 1){
      /* Pick the first interface returned */
      interface = strdup(direntries[0]->d_name);
      if(debug){
	fprintf_plus(stderr, "Using interface \"%s\"\n", interface);
      }
      if(interface == NULL){
	perror_plus("malloc");
	free(direntries);
	exitcode = EXIT_FAILURE;
	goto end;
      }
      free(direntries);
    } else {
      free(direntries);
      fprintf_plus(stderr, "Could not find a network interface\n");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  }
  
  /* Initialize Avahi early so avahi_simple_poll_quit() can be called
     from the signal handler */
  /* Initialize the pseudo-RNG for Avahi */
  srand((unsigned int) time(NULL));
  mc.simple_poll = avahi_simple_poll_new();
  if(mc.simple_poll == NULL){
    fprintf_plus(stderr,
		 "Avahi: Failed to create simple poll object.\n");
    exitcode = EX_UNAVAILABLE;
    goto end;
  }
  
  sigemptyset(&sigterm_action.sa_mask);
  ret = sigaddset(&sigterm_action.sa_mask, SIGINT);
  if(ret == -1){
    perror_plus("sigaddset");
    exitcode = EX_OSERR;
    goto end;
  }
  ret = sigaddset(&sigterm_action.sa_mask, SIGHUP);
  if(ret == -1){
    perror_plus("sigaddset");
    exitcode = EX_OSERR;
    goto end;
  }
  ret = sigaddset(&sigterm_action.sa_mask, SIGTERM);
  if(ret == -1){
    perror_plus("sigaddset");
    exitcode = EX_OSERR;
    goto end;
  }
  /* Need to check if the handler is SIG_IGN before handling:
     | [[info:libc:Initial Signal Actions]] |
     | [[info:libc:Basic Signal Handling]]  |
  */
  ret = sigaction(SIGINT, NULL, &old_sigterm_action);
  if(ret == -1){
    perror_plus("sigaction");
    return EX_OSERR;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &sigterm_action, NULL);
    if(ret == -1){
      perror_plus("sigaction");
      exitcode = EX_OSERR;
      goto end;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_sigterm_action);
  if(ret == -1){
    perror_plus("sigaction");
    return EX_OSERR;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &sigterm_action, NULL);
    if(ret == -1){
      perror_plus("sigaction");
      exitcode = EX_OSERR;
      goto end;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_sigterm_action);
  if(ret == -1){
    perror_plus("sigaction");
    return EX_OSERR;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &sigterm_action, NULL);
    if(ret == -1){
      perror_plus("sigaction");
      exitcode = EX_OSERR;
      goto end;
    }
  }
  
  /* If the interface is down, bring it up */
  if(strcmp(interface, "none") != 0){
    if_index = (AvahiIfIndex) if_nametoindex(interface);
    if(if_index == 0){
      fprintf_plus(stderr, "No such interface: \"%s\"\n", interface);
      exitcode = EX_UNAVAILABLE;
      goto end;
    }
    
    if(quit_now){
      goto end;
    }
    
    /* Re-raise priviliges */
    errno = 0;
    ret = seteuid(0);
    if(ret == -1){
      perror_plus("seteuid");
    }
    
#ifdef __linux__
    /* Lower kernel loglevel to KERN_NOTICE to avoid KERN_INFO
       messages about the network interface to mess up the prompt */
    ret = klogctl(8, NULL, 5);
    bool restore_loglevel = true;
    if(ret == -1){
      restore_loglevel = false;
      perror_plus("klogctl");
    }
#endif	/* __linux__ */
    
    sd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if(sd < 0){
      perror_plus("socket");
      exitcode = EX_OSERR;
#ifdef __linux__
      if(restore_loglevel){
	ret = klogctl(7, NULL, 0);
	if(ret == -1){
	  perror_plus("klogctl");
	}
      }
#endif	/* __linux__ */
      /* Lower privileges */
      errno = 0;
      ret = seteuid(uid);
      if(ret == -1){
	perror_plus("seteuid");
      }
      goto end;
    }
    strcpy(network.ifr_name, interface);
    ret = ioctl(sd, SIOCGIFFLAGS, &network);
    if(ret == -1){
      perror_plus("ioctl SIOCGIFFLAGS");
#ifdef __linux__
      if(restore_loglevel){
	ret = klogctl(7, NULL, 0);
	if(ret == -1){
	  perror_plus("klogctl");
	}
      }
#endif	/* __linux__ */
      exitcode = EX_OSERR;
      /* Lower privileges */
      errno = 0;
      ret = seteuid(uid);
      if(ret == -1){
	perror_plus("seteuid");
      }
      goto end;
    }
    if((network.ifr_flags & IFF_UP) == 0){
      network.ifr_flags |= IFF_UP;
      take_down_interface = true;
      ret = ioctl(sd, SIOCSIFFLAGS, &network);
      if(ret == -1){
	take_down_interface = false;
	perror_plus("ioctl SIOCSIFFLAGS +IFF_UP");
	exitcode = EX_OSERR;
#ifdef __linux__
	if(restore_loglevel){
	  ret = klogctl(7, NULL, 0);
	  if(ret == -1){
	    perror_plus("klogctl");
	  }
	}
#endif	/* __linux__ */
	/* Lower privileges */
	errno = 0;
	ret = seteuid(uid);
	if(ret == -1){
	  perror_plus("seteuid");
	}
	goto end;
      }
    }
    /* Sleep checking until interface is running.
       Check every 0.25s, up to total time of delay */
    for(int i=0; i < delay * 4; i++){
      ret = ioctl(sd, SIOCGIFFLAGS, &network);
      if(ret == -1){
	perror_plus("ioctl SIOCGIFFLAGS");
      } else if(network.ifr_flags & IFF_RUNNING){
	break;
      }
      struct timespec sleeptime = { .tv_nsec = 250000000 };
      ret = nanosleep(&sleeptime, NULL);
      if(ret == -1 and errno != EINTR){
	perror_plus("nanosleep");
      }
    }
    if(not take_down_interface){
      /* We won't need the socket anymore */
      ret = (int)TEMP_FAILURE_RETRY(close(sd));
      if(ret == -1){
	perror_plus("close");
      }
    }
#ifdef __linux__
    if(restore_loglevel){
      /* Restores kernel loglevel to default */
      ret = klogctl(7, NULL, 0);
      if(ret == -1){
	perror_plus("klogctl");
      }
    }
#endif	/* __linux__ */
    /* Lower privileges */
    errno = 0;
    /* Lower privileges */
    ret = seteuid(uid);
    if(ret == -1){
      perror_plus("seteuid");
    }
  }
  
  if(quit_now){
    goto end;
  }
  
  ret = init_gnutls_global(pubkey, seckey);
  if(ret == -1){
    fprintf_plus(stderr, "init_gnutls_global failed\n");
    exitcode = EX_UNAVAILABLE;
    goto end;
  } else {
    gnutls_initialized = true;
  }
  
  if(quit_now){
    goto end;
  }
  
  if(mkdtemp(tempdir) == NULL){
    perror_plus("mkdtemp");
    goto end;
  }
  tempdir_created = true;
  
  if(quit_now){
    goto end;
  }
  
  if(not init_gpgme(pubkey, seckey, tempdir)){
    fprintf_plus(stderr, "init_gpgme failed\n");
    exitcode = EX_UNAVAILABLE;
    goto end;
  } else {
    gpgme_initialized = true;
  }
  
  if(quit_now){
    goto end;
  }
  
  if(connect_to != NULL){
    /* Connect directly, do not use Zeroconf */
    /* (Mainly meant for debugging) */
    char *address = strrchr(connect_to, ':');
    if(address == NULL){
      fprintf_plus(stderr, "No colon in address\n");
      exitcode = EX_USAGE;
      goto end;
    }
    
    if(quit_now){
      goto end;
    }
    
    uint16_t port;
    errno = 0;
    tmpmax = strtoimax(address+1, &tmp, 10);
    if(errno != 0 or tmp == address+1 or *tmp != '\0'
       or tmpmax != (uint16_t)tmpmax){
      fprintf_plus(stderr, "Bad port number\n");
      exitcode = EX_USAGE;
      goto end;
    }
  
    if(quit_now){
      goto end;
    }
    
    port = (uint16_t)tmpmax;
    *address = '\0';
    /* Colon in address indicates IPv6 */
    int af;
    if(strchr(connect_to, ':') != NULL){
      af = AF_INET6;
      /* Accept [] around IPv6 address - see RFC 5952 */
      if(connect_to[0] == '[' and address[-1] == ']')
	{
	  connect_to++;
	  address[-1] = '\0';
	}
    } else {
      af = AF_INET;
    }
    address = connect_to;
    
    if(quit_now){
      goto end;
    }
    
    while(not quit_now){
      ret = start_mandos_communication(address, port, if_index, af);
      if(quit_now or ret == 0){
	break;
      }
      if(debug){
	fprintf_plus(stderr, "Retrying in %d seconds\n",
		     (int)retry_interval);
      }
      sleep((int)retry_interval);
    }
    
    if (not quit_now){
      exitcode = EXIT_SUCCESS;
    }
    
    goto end;
  }
  
  if(quit_now){
    goto end;
  }
  
  {
    AvahiServerConfig config;
    /* Do not publish any local Zeroconf records */
    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;
    
    /* Allocate a new server */
    mc.server = avahi_server_new(avahi_simple_poll_get
				 (mc.simple_poll), &config, NULL,
				 NULL, &error);
    
    /* Free the Avahi configuration data */
    avahi_server_config_free(&config);
  }
  
  /* Check if creating the Avahi server object succeeded */
  if(mc.server == NULL){
    fprintf_plus(stderr, "Failed to create Avahi server: %s\n",
		 avahi_strerror(error));
    exitcode = EX_UNAVAILABLE;
    goto end;
  }
  
  if(quit_now){
    goto end;
  }
  
  /* Create the Avahi service browser */
  sb = avahi_s_service_browser_new(mc.server, if_index,
				   AVAHI_PROTO_UNSPEC, "_mandos._tcp",
				   NULL, 0, browse_callback, NULL);
  if(sb == NULL){
    fprintf_plus(stderr, "Failed to create service browser: %s\n",
		 avahi_strerror(avahi_server_errno(mc.server)));
    exitcode = EX_UNAVAILABLE;
    goto end;
  }
  
  if(quit_now){
    goto end;
  }
  
  /* Run the main loop */
  
  if(debug){
    fprintf_plus(stderr, "Starting Avahi loop search\n");
  }

  ret = avahi_loop_with_timeout(mc.simple_poll,
				(int)(retry_interval * 1000));
  if(debug){
    fprintf_plus(stderr, "avahi_loop_with_timeout exited %s\n",
		 (ret == 0) ? "successfully" : "with error");
  }
  
 end:
  
  if(debug){
    fprintf_plus(stderr, "%s exiting\n", argv[0]);
  }
  
  /* Cleanup things */
  if(sb != NULL)
    avahi_s_service_browser_free(sb);
  
  if(mc.server != NULL)
    avahi_server_free(mc.server);
  
  if(mc.simple_poll != NULL)
    avahi_simple_poll_free(mc.simple_poll);
  
  if(gnutls_initialized){
    gnutls_certificate_free_credentials(mc.cred);
    gnutls_global_deinit();
    gnutls_dh_params_deinit(mc.dh_params);
  }
  
  if(gpgme_initialized){
    gpgme_release(mc.ctx);
  }
  
  /* Cleans up the circular linked list of Mandos servers the client
     has seen */
  if(mc.current_server != NULL){
    mc.current_server->prev->next = NULL;
    while(mc.current_server != NULL){
      server *next = mc.current_server->next;
      free(mc.current_server);
      mc.current_server = next;
    }
  }
  
  /* Run network hooks */
  run_network_hooks("stop", interface, delay);
  
  /* Re-raise priviliges */
  {
    errno = 0;
    ret = seteuid(0);
    if(ret == -1){
      perror_plus("seteuid");
    }
    
    /* Take down the network interface */
    if(take_down_interface and geteuid() == 0){
      ret = ioctl(sd, SIOCGIFFLAGS, &network);
      if(ret == -1){
	perror_plus("ioctl SIOCGIFFLAGS");
      } else if(network.ifr_flags & IFF_UP){
	network.ifr_flags &= ~(short)IFF_UP; /* clear flag */
	ret = ioctl(sd, SIOCSIFFLAGS, &network);
	if(ret == -1){
	  perror_plus("ioctl SIOCSIFFLAGS -IFF_UP");
	}
      }
      ret = (int)TEMP_FAILURE_RETRY(close(sd));
      if(ret == -1){
	perror_plus("close");
      }
    }
  }
  /* Lower privileges permanently */
  errno = 0;
  ret = setuid(uid);
  if(ret == -1){
    perror_plus("setuid");
  }
  
  /* Removes the GPGME temp directory and all files inside */
  if(tempdir_created){
    struct dirent **direntries = NULL;
    struct dirent *direntry = NULL;
    int numentries = scandir(tempdir, &direntries, notdotentries,
			     alphasort);
    if (numentries > 0){
      for(int i = 0; i < numentries; i++){
	direntry = direntries[i];
	char *fullname = NULL;
	ret = asprintf(&fullname, "%s/%s", tempdir,
		       direntry->d_name);
	if(ret < 0){
	  perror_plus("asprintf");
	  continue;
	}
	ret = remove(fullname);
	if(ret == -1){
	  fprintf_plus(stderr, "remove(\"%s\"): %s\n", fullname,
		       strerror(errno));
	}
	free(fullname);
      }
    }

    /* need to clean even if 0 because man page doesn't specify */
    free(direntries);
    if (numentries == -1){
      perror_plus("scandir");
    }
    ret = rmdir(tempdir);
    if(ret == -1 and errno != ENOENT){
      perror_plus("rmdir");
    }
  }
  
  if(quit_now){
    sigemptyset(&old_sigterm_action.sa_mask);
    old_sigterm_action.sa_handler = SIG_DFL;
    ret = (int)TEMP_FAILURE_RETRY(sigaction(signal_received,
					    &old_sigterm_action,
					    NULL));
    if(ret == -1){
      perror_plus("sigaction");
    }
    do {
      ret = raise(signal_received);
    } while(ret != 0 and errno == EINTR);
    if(ret != 0){
      perror_plus("raise");
      abort();
    }
    TEMP_FAILURE_RETRY(pause());
  }
  
  return exitcode;
}
