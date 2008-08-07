/*  -*- coding: utf-8 -*- */
/*
 * Mandos client - get and decrypt data from a Mandos server
 *
 * This program is partly derived from an example program for an Avahi
 * service browser, downloaded from
 * <http://avahi.org/browser/examples/core-browse-services.c>.  This
 * includes the following functions: "resolve_callback",
 * "browse_callback", and parts of "main".
 * 
 * Everything else is
 * Copyright © 2007-2008 Teddy Hogeborn & Björn Påhlsson
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
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY() */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>		/* if_nametoindex */
#include <sys/ioctl.h>          /* ioctl, ifreq, SIOCGIFFLAGS, IFF_UP,
				   SIOCSIFFLAGS */
#include <net/if.h>		/* ioctl, ifreq, SIOCGIFFLAGS, IFF_UP,
				   SIOCSIFFLAGS */

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/log.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

/* Mandos client part */
#include <sys/types.h>		/* socket(), inet_pton() */
#include <sys/socket.h>		/* socket(), struct sockaddr_in6,
				   struct in6_addr, inet_pton() */
#include <gnutls/gnutls.h>	/* All GnuTLS stuff */
#include <gnutls/openpgp.h>	/* GnuTLS with openpgp stuff */

#include <unistd.h>		/* close() */
#include <netinet/in.h>
#include <stdbool.h>		/* true */
#include <string.h>		/* memset */
#include <arpa/inet.h>		/* inet_pton() */
#include <iso646.h>		/* not */
#include <net/if.h>		/* IF_NAMESIZE */
#include <argp.h>		/* struct argp_option,
				   struct argp_state, struct argp,
				   argp_parse() */
/* GPGME */
#include <errno.h>		/* perror() */
#include <gpgme.h>

#define BUFFER_SIZE 256

bool debug = false;
static const char *keydir = "/conf/conf.d/mandos";
static const char mandos_protocol_version[] = "1";
const char *argp_program_version = "mandosclient 0.9";
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";

/* Used for passing in values through the Avahi callback functions */
typedef struct {
  AvahiSimplePoll *simple_poll;
  AvahiServer *server;
  gnutls_certificate_credentials_t cred;
  unsigned int dh_bits;
  gnutls_dh_params_t dh_params;
  const char *priority;
} mandos_context;

/*
 * Make room in "buffer" for at least BUFFER_SIZE additional bytes.
 * "buffer_capacity" is how much is currently allocated,
 * "buffer_length" is how much is already used.
 */
size_t adjustbuffer(char **buffer, size_t buffer_length,
		  size_t buffer_capacity){
  if (buffer_length + BUFFER_SIZE > buffer_capacity){
    *buffer = realloc(*buffer, buffer_capacity + BUFFER_SIZE);
    if (buffer == NULL){
      return 0;
    }
    buffer_capacity += BUFFER_SIZE;
  }
  return buffer_capacity;
}

/* 
 * Decrypt OpenPGP data using keyrings in HOMEDIR.
 * Returns -1 on error
 */
static ssize_t pgp_packet_decrypt (const char *cryptotext,
				   size_t crypto_size,
				   char **plaintext,
				   const char *homedir){
  gpgme_data_t dh_crypto, dh_plain;
  gpgme_ctx_t ctx;
  gpgme_error_t rc;
  ssize_t ret;
  size_t plaintext_capacity = 0;
  ssize_t plaintext_length = 0;
  gpgme_engine_info_t engine_info;
  
  if (debug){
    fprintf(stderr, "Trying to decrypt OpenPGP data\n");
  }
  
  /* Init GPGME */
  gpgme_check_version(NULL);
  rc = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_engine_check_version: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  
  /* Set GPGME home directory for the OpenPGP engine only */
  rc = gpgme_get_engine_info (&engine_info);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_get_engine_info: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  while(engine_info != NULL){
    if(engine_info->protocol == GPGME_PROTOCOL_OpenPGP){
      gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP,
			    engine_info->file_name, homedir);
      break;
    }
    engine_info = engine_info->next;
  }
  if(engine_info == NULL){
    fprintf(stderr, "Could not set GPGME home dir to %s\n", homedir);
    return -1;
  }
  
  /* Create new GPGME data buffer from memory cryptotext */
  rc = gpgme_data_new_from_mem(&dh_crypto, cryptotext, crypto_size,
			       0);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_data_new_from_mem: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  
  /* Create new empty GPGME data buffer for the plaintext */
  rc = gpgme_data_new(&dh_plain);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_data_new: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    gpgme_data_release(dh_crypto);
    return -1;
  }
  
  /* Create new GPGME "context" */
  rc = gpgme_new(&ctx);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_new: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    plaintext_length = -1;
    goto decrypt_end;
  }
  
  /* Decrypt data from the cryptotext data buffer to the plaintext
     data buffer */
  rc = gpgme_op_decrypt(ctx, dh_crypto, dh_plain);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_op_decrypt: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    plaintext_length = -1;
    goto decrypt_end;
  }
  
  if(debug){
    fprintf(stderr, "Decryption of OpenPGP data succeeded\n");
  }
  
  if (debug){
    gpgme_decrypt_result_t result;
    result = gpgme_op_decrypt_result(ctx);
    if (result == NULL){
      fprintf(stderr, "gpgme_op_decrypt_result failed\n");
    } else {
      fprintf(stderr, "Unsupported algorithm: %s\n",
	      result->unsupported_algorithm);
      fprintf(stderr, "Wrong key usage: %d\n",
	      result->wrong_key_usage);
      if(result->file_name != NULL){
	fprintf(stderr, "File name: %s\n", result->file_name);
      }
      gpgme_recipient_t recipient;
      recipient = result->recipients;
      if(recipient){
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
  }
  
  /* Seek back to the beginning of the GPGME plaintext data buffer */
  if (gpgme_data_seek(dh_plain, (off_t) 0, SEEK_SET) == -1){
    perror("pgpme_data_seek");
    plaintext_length = -1;
    goto decrypt_end;
  }
  
  *plaintext = NULL;
  while(true){
    plaintext_capacity = adjustbuffer(plaintext,
				      (size_t)plaintext_length,
				      plaintext_capacity);
    if (plaintext_capacity == 0){
	perror("adjustbuffer");
	plaintext_length = -1;
	goto decrypt_end;
    }
    
    ret = gpgme_data_read(dh_plain, *plaintext + plaintext_length,
			  BUFFER_SIZE);
    /* Print the data, if any */
    if (ret == 0){
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

static const char * safer_gnutls_strerror (int value) {
  const char *ret = gnutls_strerror (value);
  if (ret == NULL)
    ret = "(unknown)";
  return ret;
}

/* GnuTLS log function callback */
static void debuggnutls(__attribute__((unused)) int level,
			const char* string){
  fprintf(stderr, "GnuTLS: %s", string);
}

static int init_gnutls_global(mandos_context *mc,
			      const char *pubkeyfile,
			      const char *seckeyfile){
  int ret;
  
  if(debug){
    fprintf(stderr, "Initializing GnuTLS\n");
  }

  if ((ret = gnutls_global_init ())
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "GnuTLS global_init: %s\n",
	     safer_gnutls_strerror(ret));
    return -1;
  }
  
  if (debug){
    /* "Use a log level over 10 to enable all debugging options."
     * - GnuTLS manual
     */
    gnutls_global_set_log_level(11);
    gnutls_global_set_log_function(debuggnutls);
  }
  
  /* OpenPGP credentials */
  if ((ret = gnutls_certificate_allocate_credentials (&mc->cred))
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "GnuTLS memory error: %s\n",
	     safer_gnutls_strerror(ret));
    gnutls_global_deinit ();
    return -1;
  }
  
  if(debug){
    fprintf(stderr, "Attempting to use OpenPGP certificate %s"
	    " and keyfile %s as GnuTLS credentials\n", pubkeyfile,
	    seckeyfile);
  }
  
  ret = gnutls_certificate_set_openpgp_key_file
    (mc->cred, pubkeyfile, seckeyfile, GNUTLS_OPENPGP_FMT_BASE64);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr,
	    "Error[%d] while reading the OpenPGP key pair ('%s',"
	    " '%s')\n", ret, pubkeyfile, seckeyfile);
    fprintf(stdout, "The GnuTLS error is: %s\n",
	    safer_gnutls_strerror(ret));
    goto globalfail;
  }
  
  /* GnuTLS server initialization */
  ret = gnutls_dh_params_init(&mc->dh_params);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "Error in GnuTLS DH parameter initialization:"
	     " %s\n", safer_gnutls_strerror(ret));
    goto globalfail;
  }
  ret = gnutls_dh_params_generate2(mc->dh_params, mc->dh_bits);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "Error in GnuTLS prime generation: %s\n",
	     safer_gnutls_strerror(ret));
    goto globalfail;
  }
  
  gnutls_certificate_set_dh_params(mc->cred, mc->dh_params);

  return 0;

 globalfail:

  gnutls_certificate_free_credentials (mc->cred);
  gnutls_global_deinit ();
  return -1;

}

static int init_gnutls_session(mandos_context *mc,
			       gnutls_session_t *session){
  int ret;
  /* GnuTLS session creation */
  ret = gnutls_init(session, GNUTLS_SERVER);
  if (ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "Error in GnuTLS session initialization: %s\n",
	    safer_gnutls_strerror(ret));
  }
  
  {
    const char *err;
    ret = gnutls_priority_set_direct(*session, mc->priority, &err);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Syntax error at: %s\n", err);
      fprintf(stderr, "GnuTLS error: %s\n",
	      safer_gnutls_strerror(ret));
      gnutls_deinit (*session);
      return -1;
    }
  }
  
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE,
			       mc->cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Error setting GnuTLS credentials: %s\n",
	    safer_gnutls_strerror(ret));
    gnutls_deinit (*session);
    return -1;
  }
  
  /* ignore client certificate if any. */
  gnutls_certificate_server_set_request (*session,
					 GNUTLS_CERT_IGNORE);
  
  gnutls_dh_set_prime_bits (*session, mc->dh_bits);
  
  return 0;
}

/* Avahi log function callback */
static void empty_log(__attribute__((unused)) AvahiLogLevel level,
		      __attribute__((unused)) const char *txt){}

/* Called when a Mandos server is found */
static int start_mandos_communication(const char *ip, uint16_t port,
				      AvahiIfIndex if_index,
				      mandos_context *mc){
  int ret, tcp_sd;
  union { struct sockaddr in; struct sockaddr_in6 in6; } to;
  char *buffer = NULL;
  char *decrypted_buffer;
  size_t buffer_length = 0;
  size_t buffer_capacity = 0;
  ssize_t decrypted_buffer_size;
  size_t written;
  int retval = 0;
  char interface[IF_NAMESIZE];
  gnutls_session_t session;
  
  ret = init_gnutls_session (mc, &session);
  if (ret != 0){
    return -1;
  }
  
  if(debug){
    fprintf(stderr, "Setting up a tcp connection to %s, port %d\n",
	    ip, port);
  }
  
  tcp_sd = socket(PF_INET6, SOCK_STREAM, 0);
  if(tcp_sd < 0) {
    perror("socket");
    return -1;
  }

  if(debug){
    if(if_indextoname((unsigned int)if_index, interface) == NULL){
      perror("if_indextoname");
      return -1;
    }
    fprintf(stderr, "Binding to interface %s\n", interface);
  }
  
  memset(&to,0,sizeof(to));	/* Spurious warning */
  to.in6.sin6_family = AF_INET6;
  /* It would be nice to have a way to detect if we were passed an
     IPv4 address here.   Now we assume an IPv6 address. */
  ret = inet_pton(AF_INET6, ip, &to.in6.sin6_addr);
  if (ret < 0 ){
    perror("inet_pton");
    return -1;
  }
  if(ret == 0){
    fprintf(stderr, "Bad address: %s\n", ip);
    return -1;
  }
  to.in6.sin6_port = htons(port);	/* Spurious warning */
  
  to.in6.sin6_scope_id = (uint32_t)if_index;
  
  if(debug){
    fprintf(stderr, "Connection to: %s, port %d\n", ip, port);
    char addrstr[INET6_ADDRSTRLEN] = "";
    if(inet_ntop(to.in6.sin6_family, &(to.in6.sin6_addr), addrstr,
		 sizeof(addrstr)) == NULL){
      perror("inet_ntop");
    } else {
      if(strcmp(addrstr, ip) != 0){
	fprintf(stderr, "Canonical address form: %s\n", addrstr);
      }
    }
  }
  
  ret = connect(tcp_sd, &to.in, sizeof(to));
  if (ret < 0){
    perror("connect");
    return -1;
  }

  const char *out = mandos_protocol_version;
  written = 0;
  while (true){
    size_t out_size = strlen(out);
    ret = TEMP_FAILURE_RETRY(write(tcp_sd, out + written,
				   out_size - written));
    if (ret == -1){
      perror("write");
      retval = -1;
      goto mandos_end;
    }
    written += (size_t)ret;
    if(written < out_size){
      continue;
    } else {
      if (out == mandos_protocol_version){
	written = 0;
	out = "\r\n";
      } else {
	break;
      }
    }
  }
 
  if(debug){
    fprintf(stderr, "Establishing TLS session with %s\n", ip);
  }
  
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) tcp_sd);
  
  ret = gnutls_handshake (session);
  
  if (ret != GNUTLS_E_SUCCESS){
    if(debug){
      fprintf(stderr, "*** GnuTLS Handshake failed ***\n");
      gnutls_perror (ret);
    }
    retval = -1;
    goto mandos_end;
  }
  
  /* Read OpenPGP packet that contains the wanted password */
  
  if(debug){
    fprintf(stderr, "Retrieving pgp encrypted password from %s\n",
	    ip);
  }

  while(true){
    buffer_capacity = adjustbuffer(&buffer, buffer_length,
				   buffer_capacity);
    if (buffer_capacity == 0){
      perror("adjustbuffer");
      retval = -1;
      goto mandos_end;
    }
    
    ret = gnutls_record_recv(session, buffer+buffer_length,
			     BUFFER_SIZE);
    if (ret == 0){
      break;
    }
    if (ret < 0){
      switch(ret){
      case GNUTLS_E_INTERRUPTED:
      case GNUTLS_E_AGAIN:
	break;
      case GNUTLS_E_REHANDSHAKE:
	ret = gnutls_handshake (session);
	if (ret < 0){
	  fprintf(stderr, "*** GnuTLS Re-handshake failed ***\n");
	  gnutls_perror (ret);
	  retval = -1;
	  goto mandos_end;
	}
	break;
      default:
	fprintf(stderr, "Unknown error while reading data from"
		" encrypted session with Mandos server\n");
	retval = -1;
	gnutls_bye (session, GNUTLS_SHUT_RDWR);
	goto mandos_end;
      }
    } else {
      buffer_length += (size_t) ret;
    }
  }
  
  if(debug){
    fprintf(stderr, "Closing TLS session\n");
  }
  
  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  
  if (buffer_length > 0){
    decrypted_buffer_size = pgp_packet_decrypt(buffer,
					       buffer_length,
					       &decrypted_buffer,
					       keydir);
    if (decrypted_buffer_size >= 0){
      written = 0;
      while(written < (size_t) decrypted_buffer_size){
	ret = (int)fwrite (decrypted_buffer + written, 1,
			   (size_t)decrypted_buffer_size - written,
			   stdout);
	if(ret == 0 and ferror(stdout)){
	  if(debug){
	    fprintf(stderr, "Error writing encrypted data: %s\n",
		    strerror(errno));
	  }
	  retval = -1;
	  break;
	}
	written += (size_t)ret;
      }
      free(decrypted_buffer);
    } else {
      retval = -1;
    }
  }
  
  /* Shutdown procedure */
  
 mandos_end:
  free(buffer);
  close(tcp_sd);
  gnutls_deinit (session);
  return retval;
}

static void resolve_callback(AvahiSServiceResolver *r,
			     AvahiIfIndex interface,
			     AVAHI_GCC_UNUSED AvahiProtocol protocol,
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
			     void* userdata) {
  mandos_context *mc = userdata;
  assert(r);			/* Spurious warning */
  
  /* Called whenever a service has been resolved successfully or
     timed out */
  
  switch (event) {
  default:
  case AVAHI_RESOLVER_FAILURE:
    fprintf(stderr, "(Avahi Resolver) Failed to resolve service '%s'"
	    " of type '%s' in domain '%s': %s\n", name, type, domain,
	    avahi_strerror(avahi_server_errno(mc->server)));
    break;
    
  case AVAHI_RESOLVER_FOUND:
    {
      char ip[AVAHI_ADDRESS_STR_MAX];
      avahi_address_snprint(ip, sizeof(ip), address);
      if(debug){
	fprintf(stderr, "Mandos server \"%s\" found on %s (%s, %d) on"
		" port %d\n", name, host_name, ip, interface, port);
      }
      int ret = start_mandos_communication(ip, port, interface, mc);
      if (ret == 0){
	exit(EXIT_SUCCESS);
      }
    }
  }
  avahi_s_service_resolver_free(r);
}

static void browse_callback( AvahiSServiceBrowser *b,
			     AvahiIfIndex interface,
			     AvahiProtocol protocol,
			     AvahiBrowserEvent event,
			     const char *name,
			     const char *type,
			     const char *domain,
			     AVAHI_GCC_UNUSED AvahiLookupResultFlags
			     flags,
			     void* userdata) {
  mandos_context *mc = userdata;
  assert(b);			/* Spurious warning */
  
  /* Called whenever a new services becomes available on the LAN or
     is removed from the LAN */
  
  switch (event) {
  default:
  case AVAHI_BROWSER_FAILURE:
    
    fprintf(stderr, "(Avahi browser) %s\n",
	    avahi_strerror(avahi_server_errno(mc->server)));
    avahi_simple_poll_quit(mc->simple_poll);
    return;
    
  case AVAHI_BROWSER_NEW:
    /* We ignore the returned Avahi resolver object. In the callback
       function we free it. If the Avahi server is terminated before
       the callback function is called the Avahi server will free the
       resolver for us. */
    
    if (!(avahi_s_service_resolver_new(mc->server, interface,
				       protocol, name, type, domain,
				       AVAHI_PROTO_INET6, 0,
				       resolve_callback, mc)))
      fprintf(stderr, "Avahi: Failed to resolve service '%s': %s\n",
	      name, avahi_strerror(avahi_server_errno(mc->server)));
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

/* Combines file name and path and returns the malloced new
   string. some sane checks could/should be added */
static const char *combinepath(const char *first, const char *second){
  size_t f_len = strlen(first);
  size_t s_len = strlen(second);
  char *tmp = malloc(f_len + s_len + 2);
  if (tmp == NULL){
    return NULL;
  }
  if(f_len > 0){
    memcpy(tmp, first, f_len);	/* Spurious warning */
  }
  tmp[f_len] = '/';
  if(s_len > 0){
    memcpy(tmp + f_len + 1, second, s_len); /* Spurious warning */
  }
  tmp[f_len + 1 + s_len] = '\0';
  return tmp;
}


int main(int argc, char *argv[]){
    AvahiSServiceBrowser *sb = NULL;
    int error;
    int ret;
    int exitcode = EXIT_SUCCESS;
    const char *interface = "eth0";
    struct ifreq network;
    int sd;
    uid_t uid;
    gid_t gid;
    char *connect_to = NULL;
    AvahiIfIndex if_index = AVAHI_IF_UNSPEC;
    const char *pubkeyfile = "pubkey.txt";
    const char *seckeyfile = "seckey.txt";
    mandos_context mc = { .simple_poll = NULL, .server = NULL,
			  .dh_bits = 1024, .priority = "SECURE256"};
    bool gnutls_initalized = false;
    
    {
      struct argp_option options[] = {
	{ .name = "debug", .key = 128,
	  .doc = "Debug mode", .group = 3 },
	{ .name = "connect", .key = 'c',
	  .arg = "IP",
	  .doc = "Connect directly to a sepcified mandos server",
	  .group = 1 },
	{ .name = "interface", .key = 'i',
	  .arg = "INTERFACE",
	  .doc = "Interface that Avahi will conntect through",
	  .group = 1 },
	{ .name = "keydir", .key = 'd',
	  .arg = "KEYDIR",
	  .doc = "Directory where the openpgp keyring is",
	  .group = 1 },
	{ .name = "seckey", .key = 's',
	  .arg = "SECKEY",
	  .doc = "Secret openpgp key for gnutls authentication",
	  .group = 1 },
	{ .name = "pubkey", .key = 'p',
	  .arg = "PUBKEY",
	  .doc = "Public openpgp key for gnutls authentication",
	  .group = 2 },
	{ .name = "dh-bits", .key = 129,
	  .arg = "BITS",
	  .doc = "dh-bits to use in gnutls communication",
	  .group = 2 },
	{ .name = "priority", .key = 130,
	  .arg = "PRIORITY",
	  .doc = "GNUTLS priority", .group = 1 },
	{ .name = NULL }
      };

      
      error_t parse_opt (int key, char *arg,
			 struct argp_state *state) {
	/* Get the INPUT argument from `argp_parse', which we know is
	   a pointer to our plugin list pointer. */
	switch (key) {
	case 128:
	  debug = true;
	  break;
	case 'c':
	  connect_to = arg;
	  break;
	case 'i':
	  interface = arg;
	  break;
	case 'd':
	  keydir = arg;
	  break;
	case 's':
	  seckeyfile = arg;
	  break;
	case 'p':
	  pubkeyfile = arg;
	  break;
	case 129:
	  errno = 0;
	  mc.dh_bits = (unsigned int) strtol(arg, NULL, 10);
	  if (errno){
	    perror("strtol");
	    exit(EXIT_FAILURE);
	  }
	  break;
	case 130:
	  mc.priority = arg;
	  break;
	case ARGP_KEY_ARG:
	  argp_usage (state);
	  break;
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
			   " passwords from mandos server" };
      argp_parse (&argp, argc, argv, 0, 0, NULL);
    }
      
    pubkeyfile = combinepath(keydir, pubkeyfile);
    if (pubkeyfile == NULL){
      perror("combinepath");
      exitcode = EXIT_FAILURE;
      goto end;
    }
    
    seckeyfile = combinepath(keydir, seckeyfile);
    if (seckeyfile == NULL){
      perror("combinepath");
      goto end;
    }

    ret = init_gnutls_global(&mc, pubkeyfile, seckeyfile);
    if (ret == -1){
      fprintf(stderr, "init_gnutls_global\n");
      goto end;
    } else {
      gnutls_initalized = true;
    }

    uid = getuid();
    gid = getgid();

    ret = setuid(uid);
    if (ret == -1){
      perror("setuid");
    }
    
    setgid(gid);
    if (ret == -1){
      perror("setgid");
    }
    
    if_index = (AvahiIfIndex) if_nametoindex(interface);
    if(if_index == 0){
      fprintf(stderr, "No such interface: \"%s\"\n", interface);
      exit(EXIT_FAILURE);
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
      errno = 0;
      uint16_t port = (uint16_t) strtol(address+1, NULL, 10);
      if(errno){
	perror("Bad port number");
	exitcode = EXIT_FAILURE;
	goto end;
      }
      *address = '\0';
      address = connect_to;
      ret = start_mandos_communication(address, port, if_index, &mc);
      if(ret < 0){
	exitcode = EXIT_FAILURE;
      } else {
	exitcode = EXIT_SUCCESS;
      }
      goto end;
    }
    
    /* If the interface is down, bring it up */
    {
      sd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
      if(sd < 0) {
	perror("socket");
	exitcode = EXIT_FAILURE;
	goto end;
      }
      strcpy(network.ifr_name, interface); /* Spurious warning */
      ret = ioctl(sd, SIOCGIFFLAGS, &network);
      if(ret == -1){
	perror("ioctl SIOCGIFFLAGS");
	exitcode = EXIT_FAILURE;
	goto end;
      }
      if((network.ifr_flags & IFF_UP) == 0){
	network.ifr_flags |= IFF_UP;
	ret = ioctl(sd, SIOCSIFFLAGS, &network);
	if(ret == -1){
	  perror("ioctl SIOCSIFFLAGS");
	  exitcode = EXIT_FAILURE;
	  goto end;
	}
      }
      close(sd);
    }
    
    if (not debug){
      avahi_set_log_function(empty_log);
    }
    
    /* Initialize the pseudo-RNG for Avahi */
    srand((unsigned int) time(NULL));
    
    /* Allocate main Avahi loop object */
    mc.simple_poll = avahi_simple_poll_new();
    if (mc.simple_poll == NULL) {
        fprintf(stderr, "Avahi: Failed to create simple poll"
		" object.\n");
	exitcode = EXIT_FAILURE;
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
    if (mc.server == NULL) {
        fprintf(stderr, "Failed to create Avahi server: %s\n",
		avahi_strerror(error));
	exitcode = EXIT_FAILURE;
        goto end;
    }
    
    /* Create the Avahi service browser */
    sb = avahi_s_service_browser_new(mc.server, if_index,
				     AVAHI_PROTO_INET6,
				     "_mandos._tcp", NULL, 0,
				     browse_callback, &mc);
    if (sb == NULL) {
        fprintf(stderr, "Failed to create service browser: %s\n",
		avahi_strerror(avahi_server_errno(mc.server)));
	exitcode = EXIT_FAILURE;
        goto end;
    }
    
    /* Run the main loop */

    if (debug){
      fprintf(stderr, "Starting Avahi loop search\n");
    }
    
    avahi_simple_poll_loop(mc.simple_poll);
    
 end:

    if (debug){
      fprintf(stderr, "%s exiting\n", argv[0]);
    }
    
    /* Cleanup things */
    if (sb != NULL)
        avahi_s_service_browser_free(sb);
    
    if (mc.server != NULL)
        avahi_server_free(mc.server);

    if (mc.simple_poll != NULL)
        avahi_simple_poll_free(mc.simple_poll);
    free(pubkeyfile);
    free(seckeyfile);

    if (gnutls_initalized){
      gnutls_certificate_free_credentials (mc.cred);
      gnutls_global_deinit ();
    }
    
    return exitcode;
}
