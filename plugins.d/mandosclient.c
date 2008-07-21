/***
  This file is part of avahi.
 
  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.
 
  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>		/* if_nametoindex */

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/log.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

//mandos client part
#include <sys/types.h>		/* socket(), setsockopt(), inet_pton() */
#include <sys/socket.h>		/* socket(), setsockopt(), struct sockaddr_in6, struct in6_addr, inet_pton() */
#include <gnutls/gnutls.h>	/* ALL GNUTLS STUFF */
#include <gnutls/openpgp.h>	/* gnutls with openpgp stuff */

#include <unistd.h>		/* close() */
#include <netinet/in.h>
#include <stdbool.h>		/* true */
#include <string.h>		/* memset */
#include <arpa/inet.h>		/* inet_pton() */
#include <iso646.h>		/* not */

// gpgme
#include <errno.h>		/* perror() */
#include <gpgme.h>

// getopt long
#include <getopt.h>

#ifndef CERT_ROOT
#define CERT_ROOT "/conf/conf.d/cryptkeyreq/"
#endif
#define CERTFILE CERT_ROOT "openpgp-client.txt"
#define KEYFILE CERT_ROOT "openpgp-client-key.txt"
#define BUFFER_SIZE 256
#define DH_BITS 1024

bool debug = false;
char *interface = "eth0";

typedef struct {
  gnutls_session_t session;
  gnutls_certificate_credentials_t cred;
  gnutls_dh_params_t dh_params;
} encrypted_session;


ssize_t gpg_packet_decrypt (char *packet, size_t packet_size, char **new_packet, char *homedir){
  gpgme_data_t dh_crypto, dh_plain;
  gpgme_ctx_t ctx;
  gpgme_error_t rc;
  ssize_t ret;
  size_t new_packet_capacity = 0;
  size_t new_packet_length = 0;
  gpgme_engine_info_t engine_info;

  if (debug){
    fprintf(stderr, "Attempting to decrypt password from gpg packet\n");
  }
  
  /* Init GPGME */
  gpgme_check_version(NULL);
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  
  /* Set GPGME home directory */
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
    fprintf(stderr, "Could not set home dir to %s\n", homedir);
    return -1;
  }
  
  /* Create new GPGME data buffer from packet buffer */
  rc = gpgme_data_new_from_mem(&dh_crypto, packet, packet_size, 0);
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
    return -1;
  }
  
  /* Create new GPGME "context" */
  rc = gpgme_new(&ctx);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_new: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }
  
  /* Decrypt data from the FILE pointer to the plaintext data buffer */
  rc = gpgme_op_decrypt(ctx, dh_crypto, dh_plain);
  if (rc != GPG_ERR_NO_ERROR){
    fprintf(stderr, "bad gpgme_op_decrypt: %s: %s\n",
	    gpgme_strsource(rc), gpgme_strerror(rc));
    return -1;
  }

  if(debug){
    fprintf(stderr, "decryption of gpg packet succeeded\n");
  }

  if (debug){
    gpgme_decrypt_result_t result;
    result = gpgme_op_decrypt_result(ctx);
    if (result == NULL){
      fprintf(stderr, "gpgme_op_decrypt_result failed\n");
    } else {
      fprintf(stderr, "Unsupported algorithm: %s\n", result->unsupported_algorithm);
      fprintf(stderr, "Wrong key usage: %d\n", result->wrong_key_usage);
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
		  recipient->status == GPG_ERR_NO_SECKEY ? "No" : "Yes");
	  recipient = recipient->next;
	}
      }
    }
  }
  
  /* Delete the GPGME FILE pointer cryptotext data buffer */
  gpgme_data_release(dh_crypto);
  
  /* Seek back to the beginning of the GPGME plaintext data buffer */
  gpgme_data_seek(dh_plain, 0, SEEK_SET);

  *new_packet = 0;
  while(true){
    if (new_packet_length + BUFFER_SIZE > new_packet_capacity){
      *new_packet = realloc(*new_packet, new_packet_capacity + BUFFER_SIZE);
      if (*new_packet == NULL){
	perror("realloc");
	return -1;
      }
      new_packet_capacity += BUFFER_SIZE;
    }
    
    ret = gpgme_data_read(dh_plain, *new_packet + new_packet_length, BUFFER_SIZE);
    /* Print the data, if any */
    if (ret == 0){
      /* If password is empty, then a incorrect error will be printed */
      break;
    }
    if(ret < 0){
      perror("gpgme_data_read");
      return -1;
    }
    new_packet_length += ret;
  }

  /* FIXME: check characters before printing to screen so to not print
     terminal control characters */
  /*   if(debug){ */
  /*     fprintf(stderr, "decrypted password is: "); */
  /*     fwrite(*new_packet, 1, new_packet_length, stderr); */
  /*     fprintf(stderr, "\n"); */
  /*   } */
  
  /* Delete the GPGME plaintext data buffer */
  gpgme_data_release(dh_plain);
  return new_packet_length;
}

static const char * safer_gnutls_strerror (int value) {
  const char *ret = gnutls_strerror (value);
  if (ret == NULL)
    ret = "(unknown)";
  return ret;
}

void debuggnutls(int level, const char* string){
  fprintf(stderr, "%s", string);
}

int initgnutls(encrypted_session *es){
  const char *err;
  int ret;

  if(debug){
    fprintf(stderr, "Initializing gnutls\n");
  }

  
  if ((ret = gnutls_global_init ())
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "global_init: %s\n", safer_gnutls_strerror(ret));
    return -1;
  }

  if (debug){
    gnutls_global_set_log_level(11);
    gnutls_global_set_log_function(debuggnutls);
  }
  

  /* openpgp credentials */
  if ((ret = gnutls_certificate_allocate_credentials (&es->cred))
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "memory error: %s\n", safer_gnutls_strerror(ret));
    return -1;
  }

  if(debug){
    fprintf(stderr, "Attempting to use openpgp certificate %s"
	    " and keyfile %s as gnutls credentials\n", CERTFILE, KEYFILE);
  }

  ret = gnutls_certificate_set_openpgp_key_file
    (es->cred, CERTFILE, KEYFILE, GNUTLS_OPENPGP_FMT_BASE64);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf
      (stderr, "Error[%d] while reading the OpenPGP key pair ('%s', '%s')\n",
       ret, CERTFILE, KEYFILE);
    fprintf(stdout, "The Error is: %s\n",
	    safer_gnutls_strerror(ret));
    return -1;
  }

  //Gnutls server initialization
  if ((ret = gnutls_dh_params_init (&es->dh_params))
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "Error in dh parameter initialization: %s\n",
	     safer_gnutls_strerror(ret));
    return -1;
  }

  if ((ret = gnutls_dh_params_generate2 (es->dh_params, DH_BITS))
      != GNUTLS_E_SUCCESS) {
    fprintf (stderr, "Error in prime generation: %s\n",
	     safer_gnutls_strerror(ret));
    return -1;
  }

  gnutls_certificate_set_dh_params (es->cred, es->dh_params);

  // Gnutls session creation
  if ((ret = gnutls_init (&es->session, GNUTLS_SERVER))
      != GNUTLS_E_SUCCESS){
    fprintf(stderr, "Error in gnutls session initialization: %s\n",
	    safer_gnutls_strerror(ret));
  }

  if ((ret = gnutls_priority_set_direct (es->session, "NORMAL", &err))
      != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Syntax error at: %s\n", err);
    fprintf(stderr, "Gnutls error: %s\n",
	    safer_gnutls_strerror(ret));
    return -1;
  }

  if ((ret = gnutls_credentials_set
       (es->session, GNUTLS_CRD_CERTIFICATE, es->cred))
      != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Error setting a credentials set: %s\n",
	    safer_gnutls_strerror(ret));
    return -1;
  }

  /* ignore client certificate if any. */
  gnutls_certificate_server_set_request (es->session, GNUTLS_CERT_IGNORE);
  
  gnutls_dh_set_prime_bits (es->session, DH_BITS);
  
  return 0;
}

void empty_log(AvahiLogLevel level, const char *txt){}

int start_mandos_communication(char *ip, uint16_t port){
  int ret, tcp_sd;
  struct sockaddr_in6 to;
  encrypted_session es;
  char *buffer = NULL;
  char *decrypted_buffer;
  size_t buffer_length = 0;
  size_t buffer_capacity = 0;
  ssize_t decrypted_buffer_size;
  int retval = 0;

  if(debug){
    fprintf(stderr, "Setting up a tcp connection to %s\n", ip);
  }
  
  tcp_sd = socket(PF_INET6, SOCK_STREAM, 0);
  if(tcp_sd < 0) {
    perror("socket");
    return -1;
  }

  if(debug){
    fprintf(stderr, "Binding to interface %s\n", interface);
  }

  ret = setsockopt(tcp_sd, SOL_SOCKET, SO_BINDTODEVICE, interface, 5);
  if(tcp_sd < 0) {
    perror("setsockopt bindtodevice");
    return -1;
  }
  
  memset(&to,0,sizeof(to));
  to.sin6_family = AF_INET6;
  ret = inet_pton(AF_INET6, ip, &to.sin6_addr);
  if (ret < 0 ){
    perror("inet_pton");
    return -1;
  }  
  if(ret == 0){
    fprintf(stderr, "Bad address: %s\n", ip);
    return -1;
  }
  to.sin6_port = htons(port);
  to.sin6_scope_id = if_nametoindex(interface);

  if(debug){
    fprintf(stderr, "Connection to: %s\n", ip);
  }
  
  ret = connect(tcp_sd, (struct sockaddr *) &to, sizeof(to));
  if (ret < 0){
    perror("connect");
    return -1;
  }
  
  ret = initgnutls (&es);
  if (ret != 0){
    retval = -1;
    return -1;
  }
    
  
  gnutls_transport_set_ptr (es.session, (gnutls_transport_ptr_t) tcp_sd);

  if(debug){
    fprintf(stderr, "Establishing tls session with %s\n", ip);
  }

  
  ret = gnutls_handshake (es.session);
  
  if (ret != GNUTLS_E_SUCCESS){
    fprintf(stderr, "\n*** Handshake failed ***\n");
    gnutls_perror (ret);
    retval = -1;
    goto exit;
  }

  //Retrieve gpg packet that contains the wanted password

  if(debug){
    fprintf(stderr, "Retrieving pgp encrypted password from %s\n", ip);
  }

  while(true){
    if (buffer_length + BUFFER_SIZE > buffer_capacity){
      buffer = realloc(buffer, buffer_capacity + BUFFER_SIZE);
      if (buffer == NULL){
	perror("realloc");
	goto exit;
      }
      buffer_capacity += BUFFER_SIZE;
    }
    
    ret = gnutls_record_recv
      (es.session, buffer+buffer_length, BUFFER_SIZE);
    if (ret == 0){
      break;
    }
    if (ret < 0){
      switch(ret){
      case GNUTLS_E_INTERRUPTED:
      case GNUTLS_E_AGAIN:
	break;
      case GNUTLS_E_REHANDSHAKE:
	ret = gnutls_handshake (es.session);
	if (ret < 0){
	  fprintf(stderr, "\n*** Handshake failed ***\n");
	  gnutls_perror (ret);
	  retval = -1;
	  goto exit;
	}
	break;
      default:
	fprintf(stderr, "Unknown error while reading data from encrypted session with mandos server\n");
	retval = -1;
	gnutls_bye (es.session, GNUTLS_SHUT_RDWR);
	goto exit;
      }
    } else {
      buffer_length += ret;
    }
  }
  
  if (buffer_length > 0){
    if ((decrypted_buffer_size = gpg_packet_decrypt(buffer, buffer_length, &decrypted_buffer, CERT_ROOT)) >= 0){
      fwrite (decrypted_buffer, 1, decrypted_buffer_size, stdout);
      free(decrypted_buffer);
    } else {
      retval = -1;
    }
  }

  //shutdown procedure

  if(debug){
    fprintf(stderr, "Closing tls session\n");
  }

  free(buffer);
  gnutls_bye (es.session, GNUTLS_SHUT_RDWR);
 exit:
  close(tcp_sd);
  gnutls_deinit (es.session);
  gnutls_certificate_free_credentials (es.cred);
  gnutls_global_deinit ();
  return retval;
}

static AvahiSimplePoll *simple_poll = NULL;
static AvahiServer *server = NULL;

static void resolve_callback(
    AvahiSServiceResolver *r,
    AVAHI_GCC_UNUSED AvahiIfIndex interface,
    AVAHI_GCC_UNUSED AvahiProtocol protocol,
    AvahiResolverEvent event,
    const char *name,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    AVAHI_GCC_UNUSED void* userdata) {
    
    assert(r);

    /* Called whenever a service has been resolved successfully or timed out */

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
            break;

        case AVAHI_RESOLVER_FOUND: {
	  char ip[AVAHI_ADDRESS_STR_MAX];
            avahi_address_snprint(ip, sizeof(ip), address);
	    if(debug){
	      fprintf(stderr, "Mandos server found at %s on port %d\n", ip, port);
	    }
	    int ret = start_mandos_communication(ip, port);
	    if (ret == 0){
	      exit(EXIT_SUCCESS);
	    } else {
	      exit(EXIT_FAILURE);
	    }
        }
    }
    avahi_s_service_resolver_free(r);
}

static void browse_callback(
    AvahiSServiceBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {
    
    AvahiServer *s = userdata;
    assert(b);

    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */

    switch (event) {

        case AVAHI_BROWSER_FAILURE:
            
            fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_server_errno(server)));
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
            /* We ignore the returned resolver object. In the callback
               function we free it. If the server is terminated before
               the callback function is called the server will free
               the resolver for us. */
            
            if (!(avahi_s_service_resolver_new(s, interface, protocol, name, type, domain, AVAHI_PROTO_INET6, 0, resolve_callback, s)))
                fprintf(stderr, "Failed to resolve service '%s': %s\n", name, avahi_strerror(avahi_server_errno(s)));
            
            break;

        case AVAHI_BROWSER_REMOVE:
            break;

        case AVAHI_BROWSER_ALL_FOR_NOW:
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            break;
    }
}

int main(AVAHI_GCC_UNUSED int argc, AVAHI_GCC_UNUSED char*argv[]) {
    AvahiServerConfig config;
    AvahiSServiceBrowser *sb = NULL;
    int error;
    int ret;
    int returncode = EXIT_SUCCESS;

    while (true){
      static struct option long_options[] = {
	{"debug", no_argument, (int *)&debug, 1},
	{"interface", required_argument, 0, 'i'},
	{0, 0, 0, 0} };

      int option_index = 0;
      ret = getopt_long (argc, argv, "i:", long_options, &option_index);

      if (ret == -1){
	break;
      }
      
      switch(ret){
      case 0:
	break;
      case 'i':
	interface = optarg;
	break;
      default:
	exit(EXIT_FAILURE);
      }
    }
    
    if (not debug){
      avahi_set_log_function(empty_log);
    }
    
    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
	
        goto exit;
    }

    /* Do not publish any local records */
    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    /* Allocate a new server */
    server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    avahi_server_config_free(&config);

    /* Check if creating the server object succeeded */
    if (!server) {
        fprintf(stderr, "Failed to create server: %s\n", avahi_strerror(error));
	returncode = EXIT_FAILURE;
        goto exit;
    }
    
    /* Create the service browser */
    if (!(sb = avahi_s_service_browser_new(server, if_nametoindex("eth0"), AVAHI_PROTO_INET6, "_mandos._tcp", NULL, 0, browse_callback, server))) {
        fprintf(stderr, "Failed to create service browser: %s\n", avahi_strerror(avahi_server_errno(server)));
	returncode = EXIT_FAILURE;
        goto exit;
    }
    
    /* Run the main loop */

    if (debug){
      fprintf(stderr, "Starting avahi loop search\n");
    }
    
    avahi_simple_poll_loop(simple_poll);
    
exit:

    if (debug){
      fprintf(stderr, "%s exiting\n", argv[0]);
    }
    
    /* Cleanup things */
    if (sb)
        avahi_s_service_browser_free(sb);
    
    if (server)
        avahi_server_free(server);

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    return returncode;
}
