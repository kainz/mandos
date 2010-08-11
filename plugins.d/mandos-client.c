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
 * Copyright © 2008,2009 Teddy Hogeborn
 * Copyright © 2008,2009 Björn Påhlsson
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
 * Contact the authors at <mandos@fukt.bsnet.se>.
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
#include <stdlib.h> 		/* free(), EXIT_SUCCESS, EXIT_FAILURE,
				   srand(), strtof(), abort() */
#include <stdbool.h>		/* bool, false, true */
#include <string.h>		/* memset(), strcmp(), strlen(),
				   strerror(), asprintf(), strcpy() */
#include <sys/ioctl.h>		/* ioctl */
#include <sys/types.h>		/* socket(), inet_pton(), sockaddr,
				   sockaddr_in6, PF_INET6,
				   SOCK_STREAM, uid_t, gid_t, open(),
				   opendir(), DIR */
#include <sys/stat.h>		/* open() */
#include <sys/socket.h>		/* socket(), struct sockaddr_in6,
				   inet_pton(), connect() */
#include <fcntl.h>		/* open() */
#include <dirent.h>		/* opendir(), struct dirent, readdir()
				 */
#include <inttypes.h>		/* PRIu16, PRIdMAX, intmax_t,
				   strtoimax() */
#include <assert.h>		/* assert() */
#include <errno.h>		/* perror(), errno */
#include <time.h>		/* nanosleep(), time() */
#include <net/if.h>		/* ioctl, ifreq, SIOCGIFFLAGS, IFF_UP,
				   SIOCSIFFLAGS, if_indextoname(),
				   if_nametoindex(), IF_NAMESIZE */
#include <netinet/in.h>		/* IN6_IS_ADDR_LINKLOCAL,
				   INET_ADDRSTRLEN, INET6_ADDRSTRLEN
				*/
#include <unistd.h>		/* close(), SEEK_SET, off_t, write(),
				   getuid(), getgid(), seteuid(),
				   setgid(), pause() */
#include <arpa/inet.h>		/* inet_pton(), htons */
#include <iso646.h>		/* not, or, and */
#include <argp.h>		/* struct argp_option, error_t, struct
				   argp_state, struct argp,
				   argp_parse(), ARGP_KEY_ARG,
				   ARGP_KEY_END, ARGP_ERR_UNKNOWN */
#include <signal.h>		/* sigemptyset(), sigaddset(),
				   sigaction(), SIGTERM, sig_atomic_t,
				   raise() */

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

bool debug = false;
static const char mandos_protocol_version[] = "1";
const char *argp_program_version = "mandos-client " VERSION;
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";
static const char sys_class_net[] = "/sys/class/net";
char *connect_to = NULL;

/* Used for passing in values through the Avahi callback functions */
typedef struct {
  AvahiSimplePoll *simple_poll;
  AvahiServer *server;
  gnutls_certificate_credentials_t cred;
  unsigned int dh_bits;
  gnutls_dh_params_t dh_params;
  const char *priority;
  gpgme_ctx_t ctx;
} mandos_context;

/* global context so signal handler can reach it*/
mandos_context mc = { .simple_poll = NULL, .server = NULL,
		      .dh_bits = 1024, .priority = "SECURE256"
		      ":!CTYPE-X.509:+CTYPE-OPENPGP" };

sig_atomic_t quit_now = 0;
int signal_received = 0;

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

/* 
 * Initialize GPGME.
 */
static bool init_gpgme(const char *seckey,
		       const char *pubkey, const char *tempdir){
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
      perror("open");
      return false;
    }
    
    rc = gpgme_data_new_from_fd(&pgp_data, fd);
    if(rc != GPG_ERR_NO_ERROR){
      fprintf(stderr, "bad gpgme_data_new_from_fd: %s: %s\n",
	      gpgme_strsource(rc), gpgme_strerror(rc));
      return false;
    }
    
    rc = gpgme_op_import(mc.ctx, pgp_data);
    if(rc != GPG_ERR_NO_ERROR){
      fprintf(stderr, "bad gpgme_op_import: %s: %s\n",
	      gpgme_strsource(rc), gpgme_strerror(rc));
      return false;
    }
    
    ret = (int)TEMP_FAILURE_RETRY(close(fd));
    if(ret == -1){
      perror("close");
    }
    gpgme_data_release(pgp_data);
    return true;
  }
  
  if(debug){
    fprintf(stderr, "Initializing GPGME\n");
  }
  
  /* Init GPGME */
  gpgme_check_version(NULL);
  rc = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_engine_check_version: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return false;
  }
  
    /* Set GPGME home directory for the OpenPGP engine only */
  rc = gpgme_get_engine_info(&engine_info);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_get_engine_info: %s: %s\n",
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
    fprintf(stderr, "Could not set GPGME home dir to %s\n", tempdir);
    return false;
  }
  
  /* Create new GPGME "context" */
  rc = gpgme_new(&(mc.ctx));
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_new: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
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
    fprintf(stderr, "Trying to decrypt OpenPGP data\n");
  }
  
  /* Create new GPGME data buffer from memory cryptotext */
  rc = gpgme_data_new_from_mem(&dh_crypto, cryptotext, crypto_size,
			       0);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_data_new_from_mem: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  
  /* Create new empty GPGME data buffer for the plaintext */
  rc = gpgme_data_new(&dh_plain);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_data_new: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    gpgme_data_release(dh_crypto);
    return -1;
  }
  
  /* Decrypt data from the cryptotext data buffer to the plaintext
     data buffer */
  rc = gpgme_op_decrypt(mc.ctx, dh_crypto, dh_plain);
  if(rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_op_decrypt: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    plaintext_length = -1;
    if(debug){
      gpgme_decrypt_result_t result;
      result = gpgme_op_decrypt_result(mc.ctx);
      if(result == NULL){
	fprintf(stderr, "gpgme_op_decrypt_result failed\n");
      } else {
	fprintf(stderr, "Unsupported algorithm: %s\n",
		result->unsupported_algorithm);
	fprintf(stderr, "Wrong key usage: %u\n",
		result->wrong_key_usage);
	if(result->file_name != NULL){
	  fprintf(stderr, "File name: %s\n", result->file_name);
	}
	gpgme_recipient_t recipient;
	recipient = result->recipients;
	while(recipient != NULL){
	  fprintf(stderr, "Public key algorithm: %s\n",
		  gpgme_pubkey_algo_name(recipient->pubkey_algo));
	  fprintf(stderr, "Key ID: %s\n", recipient->keyid);
	  fprintf(stderr, "Secret key available: %s\n",
		  recipient->status == GPG_ERR_NO_SECKEY
		  ? "No" : "Yes");
	  recipient = recipient->next;
	}
      }
    }
    goto decrypt_end;
  }
  
  if(debug){
    fprintf(stderr, "Decryption of OpenPGP data succeeded\n");
  }
  
  /* Seek back to the beginning of the GPGME plaintext data buffer */
  if(gpgme_data_seek(dh_plain, (off_t)0, SEEK_SET) == -1){
    perror("gpgme_data_seek");
    plaintext_length = -1;
    goto decrypt_end;
  }
  
  *plaintext = NULL;
  while(true){
    plaintext_capacity = incbuffer(plaintext,
				      (size_t)plaintext_length,
				      plaintext_capacity);
    if(plaintext_capacity == 0){
	perror("incbuffer");
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
      perror("gpgme_data_read");
      plaintext_length = -1;
      goto decrypt_end;
    }
    plaintext_length += ret;
  }
  
  if(debug){
    fprintf(stderr, "Decrypted password is: ");
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
  fprintf(stderr, "GnuTLS: %s", string);
}

static int init_gnutls_global(const char *pubkeyfilename,
			      const char *seckeyfilename){
  int ret;
  
  if(debug){
    fprintf(stderr, "Initializing GnuTLS\n");
  }
  
  ret = gnutls_global_init();
  if(ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "GnuTLS global_init: %s\n",
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
  gnutls_certificate_allocate_credentials(&mc.cred);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "GnuTLS memory error: %s\n", /* Spurious warning
						    from
						    -Wunreachable-code
						 */
	    safer_gnutls_strerror(ret));
    gnutls_global_deinit();
    return -1;
  }
  
  if(debug){
    fprintf(stderr, "Attempting to use OpenPGP public key %s and"
	    " secret key %s as GnuTLS credentials\n", pubkeyfilename,
	    seckeyfilename);
  }
  
  ret = gnutls_certificate_set_openpgp_key_file
    (mc.cred, pubkeyfilename, seckeyfilename,
     GNUTLS_OPENPGP_FMT_BASE64);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf(stderr,
	    "Error[%d] while reading the OpenPGP key pair ('%s',"
	    " '%s')\n", ret, pubkeyfilename, seckeyfilename);
    fprintf(stderr, "The GnuTLS error is: %s\n",
	    safer_gnutls_strerror(ret));
    goto globalfail;
  }
  
  /* GnuTLS server initialization */
  ret = gnutls_dh_params_init(&mc.dh_params);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "Error in GnuTLS DH parameter initialization:"
	    " %s\n", safer_gnutls_strerror(ret));
    goto globalfail;
  }
  ret = gnutls_dh_params_generate2(mc.dh_params, mc.dh_bits);
  if(ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "Error in GnuTLS prime generation: %s\n",
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
    fprintf(stderr, "Error in GnuTLS session initialization: %s\n",
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
      fprintf(stderr, "Syntax error at: %s\n", err);
      fprintf(stderr, "GnuTLS error: %s\n",
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
    fprintf(stderr, "Error setting GnuTLS credentials: %s\n",
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
  
  if(quit_now){
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
    fprintf(stderr, "Bad address family: %d\n", af);
    return -1;
  }
  
  ret = init_gnutls_session(&session);
  if(ret != 0){
    return -1;
  }
  
  if(debug){
    fprintf(stderr, "Setting up a TCP connection to %s, port %" PRIu16
	    "\n", ip, port);
  }
  
  tcp_sd = socket(pf, SOCK_STREAM, 0);
  if(tcp_sd < 0){
    perror("socket");
    goto mandos_end;
  }
  
  if(quit_now){
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
    perror("inet_pton");
    goto mandos_end;
  }
  if(ret == 0){
    fprintf(stderr, "Bad address: %s\n", ip);
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
	fprintf(stderr, "An IPv6 link-local address is incomplete"
		" without a network interface\n");
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
    goto mandos_end;
  }
  
  if(debug){
    if(af == AF_INET6 and if_index != AVAHI_IF_UNSPEC){
      char interface[IF_NAMESIZE];
      if(if_indextoname((unsigned int)if_index, interface) == NULL){
	perror("if_indextoname");
      } else {
	fprintf(stderr, "Connection to: %s%%%s, port %" PRIu16 "\n",
		ip, interface, port);
      }
    } else {
      fprintf(stderr, "Connection to: %s, port %" PRIu16 "\n", ip,
	      port);
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
      perror("inet_ntop");
    } else {
      if(strcmp(addrstr, ip) != 0){
	fprintf(stderr, "Canonical address form: %s\n", addrstr);
      }
    }
  }
  
  if(quit_now){
    goto mandos_end;
  }
  
  if(af == AF_INET6){
    ret = connect(tcp_sd, &to.in6, sizeof(to));
  } else {
    ret = connect(tcp_sd, &to.in, sizeof(to)); /* IPv4 */
  }
  if(ret < 0){
    perror("connect");
    goto mandos_end;
  }
  
  if(quit_now){
    goto mandos_end;
  }
  
  const char *out = mandos_protocol_version;
  written = 0;
  while(true){
    size_t out_size = strlen(out);
    ret = (int)TEMP_FAILURE_RETRY(write(tcp_sd, out + written,
				   out_size - written));
    if(ret == -1){
      perror("write");
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
      goto mandos_end;
    }
  }
  
  if(debug){
    fprintf(stderr, "Establishing TLS session with %s\n", ip);
  }
  
  if(quit_now){
    goto mandos_end;
  }
  
  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) tcp_sd);
  
  if(quit_now){
    goto mandos_end;
  }
  
  do {
    ret = gnutls_handshake(session);
    if(quit_now){
      goto mandos_end;
    }
  } while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
  
  if(ret != GNUTLS_E_SUCCESS){
    if(debug){
      fprintf(stderr, "*** GnuTLS Handshake failed ***\n");
      gnutls_perror(ret);
    }
    goto mandos_end;
  }
  
  /* Read OpenPGP packet that contains the wanted password */
  
  if(debug){
    fprintf(stderr, "Retrieving OpenPGP encrypted password from %s\n",
	    ip);
  }
  
  while(true){
    
    if(quit_now){
      goto mandos_end;
    }
    
    buffer_capacity = incbuffer(&buffer, buffer_length,
				   buffer_capacity);
    if(buffer_capacity == 0){
      perror("incbuffer");
      goto mandos_end;
    }
    
    if(quit_now){
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
	    goto mandos_end;
	  }
	} while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
	if(ret < 0){
	  fprintf(stderr, "*** GnuTLS Re-handshake failed ***\n");
	  gnutls_perror(ret);
	  goto mandos_end;
	}
	break;
      default:
	fprintf(stderr, "Unknown error while reading data from"
		" encrypted session with Mandos server\n");
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	goto mandos_end;
      }
    } else {
      buffer_length += (size_t) sret;
    }
  }
  
  if(debug){
    fprintf(stderr, "Closing TLS session\n");
  }
  
  if(quit_now){
    goto mandos_end;
  }
  
  do {
    ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
    if(quit_now){
      goto mandos_end;
    }
  } while(ret == GNUTLS_E_AGAIN or ret == GNUTLS_E_INTERRUPTED);
  
  if(buffer_length > 0){
    ssize_t decrypted_buffer_size;
    decrypted_buffer_size = pgp_packet_decrypt(buffer,
					       buffer_length,
					       &decrypted_buffer);
    if(decrypted_buffer_size >= 0){
      
      written = 0;
      while(written < (size_t) decrypted_buffer_size){
	if(quit_now){
	  goto mandos_end;
	}
	
	ret = (int)fwrite(decrypted_buffer + written, 1,
			  (size_t)decrypted_buffer_size - written,
			  stdout);
	if(ret == 0 and ferror(stdout)){
	  if(debug){
	    fprintf(stderr, "Error writing encrypted data: %s\n",
		    strerror(errno));
	  }
	  goto mandos_end;
	}
	written += (size_t)ret;
      }
      retval = 0;
    }
  }
  
  /* Shutdown procedure */
  
 mandos_end:
  free(decrypted_buffer);
  free(buffer);
  if(tcp_sd >= 0){
    ret = (int)TEMP_FAILURE_RETRY(close(tcp_sd));
  }
  if(ret == -1){
    perror("close");
  }
  gnutls_deinit(session);
  if(quit_now){
    retval = -1;
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
    fprintf(stderr, "(Avahi Resolver) Failed to resolve service '%s'"
	    " of type '%s' in domain '%s': %s\n", name, type, domain,
	    avahi_strerror(avahi_server_errno(mc.server)));
    break;
    
  case AVAHI_RESOLVER_FOUND:
    {
      char ip[AVAHI_ADDRESS_STR_MAX];
      avahi_address_snprint(ip, sizeof(ip), address);
      if(debug){
	fprintf(stderr, "Mandos server \"%s\" found on %s (%s, %"
		PRIdMAX ") on port %" PRIu16 "\n", name, host_name,
		ip, (intmax_t)interface, port);
      }
      int ret = start_mandos_communication(ip, port, interface,
					   avahi_proto_to_af(proto));
      if(ret == 0){
	avahi_simple_poll_quit(mc.simple_poll);
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
    
    fprintf(stderr, "(Avahi browser) %s\n",
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
      fprintf(stderr, "Avahi: Failed to resolve service '%s': %s\n",
	      name, avahi_strerror(avahi_server_errno(mc.server)));
    break;
    
  case AVAHI_BROWSER_REMOVE:
    break;
    
  case AVAHI_BROWSER_ALL_FOR_NOW:
  case AVAHI_BROWSER_CACHE_EXHAUSTED:
    if(debug){
      fprintf(stderr, "No Mandos server found, still searching...\n");
    }
    break;
  }
}

/* stop main loop after sigterm has been called */
static void handle_sigterm(int sig){
  if(quit_now){
    return;
  }
  quit_now = 1;
  signal_received = sig;
  int old_errno = errno;
  if(mc.simple_poll != NULL){
    avahi_simple_poll_quit(mc.simple_poll);
  }
  errno = old_errno;
}

/* 
 * This function determines if a directory entry in /sys/class/net
 * corresponds to an acceptable network device.
 * (This function is passed to scandir(3) as a filter function.)
 */
int good_interface(const struct dirent *if_entry){
  ssize_t ssret;
  char *flagname = NULL;
  int ret = asprintf(&flagname, "%s/%s/flags", sys_class_net,
		     if_entry->d_name);
  if(ret < 0){
    perror("asprintf");
    return 0;
  }
  if(if_entry->d_name[0] == '.'){
    return 0;
  }
  int flags_fd = (int)TEMP_FAILURE_RETRY(open(flagname, O_RDONLY));
  if(flags_fd == -1){
    perror("open");
    return 0;
  }
  typedef short ifreq_flags;	/* ifreq.ifr_flags in netdevice(7) */
  /* read line from flags_fd */
  ssize_t to_read = (sizeof(ifreq_flags)*2)+3; /* "0x1003\n" */
  char *flagstring = malloc((size_t)to_read+1); /* +1 for final \0 */
  flagstring[(size_t)to_read] = '\0';
  if(flagstring == NULL){
    perror("malloc");
    close(flags_fd);
    return 0;
  }
  while(to_read > 0){
    ssret = (ssize_t)TEMP_FAILURE_RETRY(read(flags_fd, flagstring,
					     (size_t)to_read));
    if(ssret == -1){
      perror("read");
      free(flagstring);
      close(flags_fd);
      return 0;
    }
    to_read -= ssret;
    if(ssret == 0){
      break;
    }
  }
  close(flags_fd);
  intmax_t tmpmax;
  char *tmp;
  errno = 0;
  tmpmax = strtoimax(flagstring, &tmp, 0);
  if(errno != 0 or tmp == flagstring or (*tmp != '\0'
					 and not (isspace(*tmp)))
     or tmpmax != (ifreq_flags)tmpmax){
    if(debug){
      fprintf(stderr, "Invalid flags \"%s\" for interface \"%s\"\n",
	      flagstring, if_entry->d_name);
    }
    free(flagstring);
    return 0;
  }
  free(flagstring);
  ifreq_flags flags = (ifreq_flags)tmpmax;
  /* Reject the loopback device */
  if(flags & IFF_LOOPBACK){
    if(debug){
      fprintf(stderr, "Rejecting loopback interface \"%s\"\n",
	      if_entry->d_name);
    }
    return 0;
  }
  /* Accept point-to-point devices only if connect_to is specified */
  if(connect_to != NULL and (flags & IFF_POINTOPOINT)){
    if(debug){
      fprintf(stderr, "Accepting point-to-point interface \"%s\"\n",
	      if_entry->d_name);
    }
    return 1;
  }
  /* Otherwise, reject non-broadcast-capable devices */
  if(not (flags & IFF_BROADCAST)){
    if(debug){
      fprintf(stderr, "Rejecting non-broadcast interface \"%s\"\n",
	      if_entry->d_name);
    }
    return 0;
  }
  /* Accept this device */
  if(debug){
    fprintf(stderr, "Interface \"%s\" is acceptable\n",
	    if_entry->d_name);
  }
  return 1;
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
  
  struct sigaction old_sigterm_action = { .sa_handler = SIG_DFL };
  struct sigaction sigterm_action = { .sa_handler = handle_sigterm };
  
  uid = getuid();
  gid = getgid();
  
  /* Lower any group privileges we might have, just to be safe */
  errno = 0;
  ret = setgid(gid);
  if(ret == -1){
    perror("setgid");
  }
  
  /* Lower user privileges (temporarily) */
  errno = 0;
  ret = seteuid(uid);
  if(ret == -1){
    perror("seteuid");
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
      { .name = NULL }
    };
    
    error_t parse_opt(int key, char *arg,
		      struct argp_state *state){
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
	  fprintf(stderr, "Bad number of DH bits\n");
	  exit(EXIT_FAILURE);
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
	  fprintf(stderr, "Bad delay\n");
	  exit(EXIT_FAILURE);
	}
	break;
      case ARGP_KEY_ARG:
	argp_usage(state);
      case ARGP_KEY_END:
	break;
      default:
	return ARGP_ERR_UNKNOWN;
      }
      return 0;
    }
    
    struct argp argp = { .options = options, .parser = parse_opt,
			 .args_doc = "",
			 .doc = "Mandos client -- Get and decrypt"
			 " passwords from a Mandos server" };
    ret = argp_parse(&argp, argc, argv, 0, 0, NULL);
    if(ret == ARGP_ERR_UNKNOWN){
      fprintf(stderr, "Unknown error while parsing arguments\n");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  }
  
  if(not debug){
    avahi_set_log_function(empty_log);
  }

  if(interface[0] == '\0'){
    struct dirent **direntries;
    ret = scandir(sys_class_net, &direntries, good_interface,
		  alphasort);
    if(ret >= 1){
      /* Pick the first good interface */
      interface = strdup(direntries[0]->d_name);
      if(debug){
	fprintf(stderr, "Using interface \"%s\"\n", interface);
      }
      if(interface == NULL){
	perror("malloc");
	free(direntries);
	exitcode = EXIT_FAILURE;
	goto end;
      }
      free(direntries);
    } else {
      free(direntries);
      fprintf(stderr, "Could not find a network interface\n");
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
    fprintf(stderr, "Avahi: Failed to create simple poll object.\n");
    exitcode = EXIT_FAILURE;
    goto end;
  }
  
  sigemptyset(&sigterm_action.sa_mask);
  ret = sigaddset(&sigterm_action.sa_mask, SIGINT);
  if(ret == -1){
    perror("sigaddset");
    exitcode = EXIT_FAILURE;
    goto end;
  }
  ret = sigaddset(&sigterm_action.sa_mask, SIGHUP);
  if(ret == -1){
    perror("sigaddset");
    exitcode = EXIT_FAILURE;
    goto end;
  }
  ret = sigaddset(&sigterm_action.sa_mask, SIGTERM);
  if(ret == -1){
    perror("sigaddset");
    exitcode = EXIT_FAILURE;
    goto end;
  }
  /* Need to check if the handler is SIG_IGN before handling:
     | [[info:libc:Initial Signal Actions]] |
     | [[info:libc:Basic Signal Handling]]  |
  */
  ret = sigaction(SIGINT, NULL, &old_sigterm_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &sigterm_action, NULL);
    if(ret == -1){
      perror("sigaction");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_sigterm_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &sigterm_action, NULL);
    if(ret == -1){
      perror("sigaction");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_sigterm_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if(old_sigterm_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &sigterm_action, NULL);
    if(ret == -1){
      perror("sigaction");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  }
  
  /* If the interface is down, bring it up */
  if(strcmp(interface, "none") != 0){
    if_index = (AvahiIfIndex) if_nametoindex(interface);
    if(if_index == 0){
      fprintf(stderr, "No such interface: \"%s\"\n", interface);
      exitcode = EXIT_FAILURE;
      goto end;
    }
    
    if(quit_now){
      goto end;
    }
    
    /* Re-raise priviliges */
    errno = 0;
    ret = seteuid(0);
    if(ret == -1){
      perror("seteuid");
    }
    
#ifdef __linux__
    /* Lower kernel loglevel to KERN_NOTICE to avoid KERN_INFO
       messages to mess up the prompt */
    ret = klogctl(8, NULL, 5);
    bool restore_loglevel = true;
    if(ret == -1){
      restore_loglevel = false;
      perror("klogctl");
    }
#endif	/* __linux__ */
    
    sd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if(sd < 0){
      perror("socket");
      exitcode = EXIT_FAILURE;
#ifdef __linux__
      if(restore_loglevel){
	ret = klogctl(7, NULL, 0);
	if(ret == -1){
	  perror("klogctl");
	}
      }
#endif	/* __linux__ */
      /* Lower privileges */
      errno = 0;
      ret = seteuid(uid);
      if(ret == -1){
	perror("seteuid");
      }
      goto end;
    }
    strcpy(network.ifr_name, interface);
    ret = ioctl(sd, SIOCGIFFLAGS, &network);
    if(ret == -1){
      perror("ioctl SIOCGIFFLAGS");
#ifdef __linux__
      if(restore_loglevel){
	ret = klogctl(7, NULL, 0);
	if(ret == -1){
	  perror("klogctl");
	}
      }
#endif	/* __linux__ */
      exitcode = EXIT_FAILURE;
      /* Lower privileges */
      errno = 0;
      ret = seteuid(uid);
      if(ret == -1){
	perror("seteuid");
      }
      goto end;
    }
    if((network.ifr_flags & IFF_UP) == 0){
      network.ifr_flags |= IFF_UP;
      take_down_interface = true;
      ret = ioctl(sd, SIOCSIFFLAGS, &network);
      if(ret == -1){
	take_down_interface = false;
	perror("ioctl SIOCSIFFLAGS +IFF_UP");
	exitcode = EXIT_FAILURE;
#ifdef __linux__
	if(restore_loglevel){
	  ret = klogctl(7, NULL, 0);
	  if(ret == -1){
	    perror("klogctl");
	  }
	}
#endif	/* __linux__ */
	/* Lower privileges */
	errno = 0;
	ret = seteuid(uid);
	if(ret == -1){
	  perror("seteuid");
	}
	goto end;
      }
    }
    /* sleep checking until interface is running */
    for(int i=0; i < delay * 4; i++){
      ret = ioctl(sd, SIOCGIFFLAGS, &network);
      if(ret == -1){
	perror("ioctl SIOCGIFFLAGS");
      } else if(network.ifr_flags & IFF_RUNNING){
	break;
      }
      struct timespec sleeptime = { .tv_nsec = 250000000 };
      ret = nanosleep(&sleeptime, NULL);
      if(ret == -1 and errno != EINTR){
	perror("nanosleep");
      }
    }
    if(not take_down_interface){
      /* We won't need the socket anymore */
      ret = (int)TEMP_FAILURE_RETRY(close(sd));
      if(ret == -1){
	perror("close");
      }
    }
#ifdef __linux__
    if(restore_loglevel){
      /* Restores kernel loglevel to default */
      ret = klogctl(7, NULL, 0);
      if(ret == -1){
	perror("klogctl");
      }
    }
#endif	/* __linux__ */
    /* Lower privileges */
    errno = 0;
    if(take_down_interface){
      /* Lower privileges */
      ret = seteuid(uid);
      if(ret == -1){
	perror("seteuid");
      }
    } else {
      /* Lower privileges permanently */
      ret = setuid(uid);
      if(ret == -1){
	perror("setuid");
      }
    }
  }
  
  if(quit_now){
    goto end;
  }
  
  ret = init_gnutls_global(pubkey, seckey);
  if(ret == -1){
    fprintf(stderr, "init_gnutls_global failed\n");
    exitcode = EXIT_FAILURE;
    goto end;
  } else {
    gnutls_initialized = true;
  }
  
  if(quit_now){
    goto end;
  }
  
  tempdir_created = true;
  if(mkdtemp(tempdir) == NULL){
    tempdir_created = false;
    perror("mkdtemp");
    goto end;
  }
  
  if(quit_now){
    goto end;
  }
  
  if(not init_gpgme(pubkey, seckey, tempdir)){
    fprintf(stderr, "init_gpgme failed\n");
    exitcode = EXIT_FAILURE;
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
      fprintf(stderr, "No colon in address\n");
      exitcode = EXIT_FAILURE;
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
      fprintf(stderr, "Bad port number\n");
      exitcode = EXIT_FAILURE;
      goto end;
    }
  
    if(quit_now){
      goto end;
    }
    
    port = (uint16_t)tmpmax;
    *address = '\0';
    address = connect_to;
    /* Colon in address indicates IPv6 */
    int af;
    if(strchr(address, ':') != NULL){
      af = AF_INET6;
    } else {
      af = AF_INET;
    }
    
    if(quit_now){
      goto end;
    }
    
    ret = start_mandos_communication(address, port, if_index, af);
    if(ret < 0){
      exitcode = EXIT_FAILURE;
    } else {
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
    fprintf(stderr, "Failed to create Avahi server: %s\n",
	    avahi_strerror(error));
    exitcode = EXIT_FAILURE;
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
    fprintf(stderr, "Failed to create service browser: %s\n",
	    avahi_strerror(avahi_server_errno(mc.server)));
    exitcode = EXIT_FAILURE;
    goto end;
  }
  
  if(quit_now){
    goto end;
  }
  
  /* Run the main loop */
  
  if(debug){
    fprintf(stderr, "Starting Avahi loop search\n");
  }
  
  avahi_simple_poll_loop(mc.simple_poll);
  
 end:
  
  if(debug){
    fprintf(stderr, "%s exiting\n", argv[0]);
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
  
  /* Take down the network interface */
  if(take_down_interface){
    /* Re-raise priviliges */
    errno = 0;
    ret = seteuid(0);
    if(ret == -1){
      perror("seteuid");
    }
    if(geteuid() == 0){
      ret = ioctl(sd, SIOCGIFFLAGS, &network);
      if(ret == -1){
	perror("ioctl SIOCGIFFLAGS");
      } else if(network.ifr_flags & IFF_UP) {
	network.ifr_flags &= ~IFF_UP; /* clear flag */
	ret = ioctl(sd, SIOCSIFFLAGS, &network);
	if(ret == -1){
	  perror("ioctl SIOCSIFFLAGS -IFF_UP");
	}
      }
      ret = (int)TEMP_FAILURE_RETRY(close(sd));
      if(ret == -1){
	perror("close");
      }
      /* Lower privileges permanently */
      errno = 0;
      ret = setuid(uid);
      if(ret == -1){
	perror("setuid");
      }
    }
  }
  
  /* Removes the temp directory used by GPGME */
  if(tempdir_created){
    DIR *d;
    struct dirent *direntry;
    d = opendir(tempdir);
    if(d == NULL){
      if(errno != ENOENT){
	perror("opendir");
      }
    } else {
      while(true){
	direntry = readdir(d);
	if(direntry == NULL){
	  break;
	}
	/* Skip "." and ".." */
	if(direntry->d_name[0] == '.'
	   and (direntry->d_name[1] == '\0'
		or (direntry->d_name[1] == '.'
		    and direntry->d_name[2] == '\0'))){
	  continue;
	}
	char *fullname = NULL;
	ret = asprintf(&fullname, "%s/%s", tempdir,
		       direntry->d_name);
	if(ret < 0){
	  perror("asprintf");
	  continue;
	}
	ret = remove(fullname);
	if(ret == -1){
	  fprintf(stderr, "remove(\"%s\"): %s\n", fullname,
		  strerror(errno));
	}
	free(fullname);
      }
      closedir(d);
    }
    ret = rmdir(tempdir);
    if(ret == -1 and errno != ENOENT){
      perror("rmdir");
    }
  }
  
  if(quit_now){
    sigemptyset(&old_sigterm_action.sa_mask);
    old_sigterm_action.sa_handler = SIG_DFL;
    ret = (int)TEMP_FAILURE_RETRY(sigaction(signal_received,
					    &old_sigterm_action,
					    NULL));
    if(ret == -1){
      perror("sigaction");
    }
    do {
      ret = raise(signal_received);
    } while(ret != 0 and errno == EINTR);
    if(ret != 0){
      perror("raise");
      abort();
    }
    TEMP_FAILURE_RETRY(pause());
  }
  
  return exitcode;
}
