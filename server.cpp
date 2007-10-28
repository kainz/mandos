extern "C" {
#include <sys/types.h> //socket, setsockopt, bind, listen, accept,
  // inet_ntop,
#include <sys/socket.h> //socket, setsockopt, bind, listen, accept,
  // inet_ntop
#include <sys/ioctl.h> //ioctl, sockaddr_ll, ifreq
#include <unistd.h> //write, close
#include <netinet/ip.h> 	// sockaddr_in
#include <gnutls/gnutls.h>
#include <gnutls/x509.h> 	// gnutls_x509_crt_init, gnutls_x509_crt_import, gnutls_x509_crt_get_dn
#include <arpa/inet.h> 		// inet_ntop, htons
#include <net/if.h> //ifreq
}

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <algorithm> 		// std::max
#include <cstdlib> 		// exit()
#include <fstream> 		// std::ifstream
#include <string> 		// std::string
#include <map> 			// std::map
#include <iostream> 		// cout
#include <ostream> 		// <<

#define SOCKET_ERR(err,s) if(err<0) {perror(s);exit(1);}

#define PORT 49001
#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"
#define CAFILE "ca.pem"
#define CRLFILE "crl.pem"
#define DH_BITS 1024

using std::string;
using std::ifstream;
using std::map;
using std::cout;

/* These are global */
gnutls_certificate_credentials_t x509_cred;
map<string,string> table;

static gnutls_dh_params_t dh_params;

static int
generate_dh_params ()
{

  /* Generate Diffie Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);

  return 0;
}

gnutls_session_t
initialize_tls_session ()
{
  gnutls_session_t session;

  gnutls_global_init ();

  gnutls_certificate_allocate_credentials (&x509_cred);
  gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE,
					  GNUTLS_X509_FMT_PEM);
  gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE,
					GNUTLS_X509_FMT_PEM);
  gnutls_certificate_set_x509_key_file (x509_cred, CERTFILE, KEYFILE,
					GNUTLS_X509_FMT_PEM);

  generate_dh_params ();
  gnutls_certificate_set_dh_params (x509_cred, dh_params);

  gnutls_init (&session, GNUTLS_SERVER);
  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  // request client certificate if any.

  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);
  gnutls_dh_set_prime_bits (session, DH_BITS);

  return session;
}


void udpreply(int &sd){
  struct sockaddr_in6 sa_cli;
  int ret;
  char buffer[512];

  {
    socklen_t sa_cli_len = sizeof(sa_cli);
    ret = recvfrom(sd, buffer, 512,0,
		   reinterpret_cast<sockaddr *>(& sa_cli), & sa_cli_len);
    SOCKET_ERR (ret, "recvfrom");
  }

  if (strncmp(buffer,"Marco", 5) == 0){
    ret = sendto(sd, "Polo", 4, 0, reinterpret_cast<sockaddr *>(& sa_cli),
		 sizeof(sa_cli));
    SOCKET_ERR (ret, "sendto");
  }

}

void tcpreply(int sd, struct sockaddr_in6 *sa_cli, gnutls_session_t session){

  int ret;
  unsigned int status;
  char buffer[512];
  int exit_status = 0;
  char dn[128];

#define DIE(s){ exit_status = s; goto tcpreply_die; }

  printf ("- TCP connection from %s, port %d\n",
	  inet_ntop (AF_INET6, &(sa_cli->sin6_addr), buffer,
		     sizeof (buffer)), ntohs (sa_cli->sin6_port));

  
  gnutls_transport_set_ptr (session, reinterpret_cast<gnutls_transport_ptr_t> (sd));
  

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      close (sd);
      gnutls_deinit (session);
      fprintf (stderr, "*** Handshake has failed (%s)\n\n",
	       gnutls_strerror (ret));
      DIE(1);
    }
  printf ("- Handshake was completed\n");

  //time to validate

  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509){
    printf("Recived certificate not X.509\n");
    DIE(1);
  }
  {
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0;
    gnutls_x509_crt_t cert;
    size_t size;
    
    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
    
    printf ("Peer provided %d certificates.\n", cert_list_size);
    
    if (cert_list_size == 0){
      printf("No certificates recived\n");
      DIE(1);
    }
    
    gnutls_x509_crt_init (&cert);
    
    // XXX -Checking only first cert, might want to check them all
    gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);
    
    size = sizeof (dn);
    gnutls_x509_crt_get_dn (cert, dn, &size);
    
    printf ("DN: %s\n", dn);
  }

  ret = gnutls_certificate_verify_peers2 (session, &status);

  if (ret < 0){
      printf ("Verify failed\n");
      DIE(1);
  }
  
  if (status & (GNUTLS_CERT_INVALID | GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_REVOKED)) {
    if (status & GNUTLS_CERT_INVALID) {
      printf ("The certificate is not trusted.\n");
    }
    
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND){
      printf ("The certificate hasn't got a known issuer.\n");
    }
    
    if (status & GNUTLS_CERT_REVOKED){
      printf ("The certificate has been revoked.\n");
    }
    DIE(1);
  }  

  if (table.find(dn) != table.end()){
    gnutls_record_send (session, table[dn].c_str(), table[dn].size());
    printf("Password sent to client\n");
  }
  else {
    printf("dn not in list of allowed clients\n");
  }

  
 tcpreply_die:
  gnutls_bye (session, GNUTLS_SHUT_WR);
  close(sd);
  gnutls_deinit (session);
  gnutls_certificate_free_credentials (x509_cred);
  gnutls_global_deinit ();
  exit(exit_status);
}


void badconfigparser(string file){

  string dn;
  string pw;
  string pwfile;
  ifstream infile (file.c_str());

  while(infile){
    getline(infile, dn, '\n');
    if(not infile){
      break;
    }
    getline(infile, pw, '\n');
    if(not infile){
      break;
    }
    getline(infile, pwfile, '\n');
    if(not infile){
      break;
    }
    if(pw.empty()){
      ifstream pwf(pwfile.c_str());
      std::string tmp;

      while(true){
	getline(pwf,tmp);
	if (not pwf){
	  break;
	}
	pw = pw + tmp + '\n';
      }
      
    }
    table[dn]=pw;
  }
  infile.close();
}
      


int main (){
  int ret, err, udp_listen_sd, tcp_listen_sd;
  struct sockaddr_in6 sa_serv;
  struct sockaddr_in6 sa_cli;

  int optval = 1;
  socklen_t client_len;

  gnutls_session_t session;

  fd_set rfds_orig;

  badconfigparser(string("clients.conf"));

  session = initialize_tls_session ();

  //UDP IPv6 socket creation
  udp_listen_sd = socket (PF_INET6, SOCK_DGRAM, 0);
  SOCKET_ERR (udp_listen_sd, "socket");

  memset (&sa_serv, '\0', sizeof (sa_serv));
  sa_serv.sin6_family = AF_INET6;
  sa_serv.sin6_addr = in6addr_any; //XXX only listen to link local?
  sa_serv.sin6_port = htons (PORT);	/* Server Port number */

  ret = setsockopt (udp_listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));
  SOCKET_ERR(ret,"setsockopt reuseaddr");

  ret = setsockopt(udp_listen_sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
  SOCKET_ERR(ret,"setsockopt bindtodevice");

  {
    int flag = 1;
    ret = setsockopt(udp_listen_sd, SOL_SOCKET, SO_BROADCAST, & flag, sizeof(flag));
    SOCKET_ERR(ret,"setsockopt broadcast");
  }

  err = bind (udp_listen_sd, reinterpret_cast<const sockaddr *> (& sa_serv),
	      sizeof (sa_serv));
  SOCKET_ERR (err, "bind");

  //UDP socket creation done


  //TCP IPv6 socket creation

  tcp_listen_sd = socket(PF_INET6, SOCK_STREAM, 0);
  SOCKET_ERR(tcp_listen_sd,"socket");

  setsockopt(tcp_listen_sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
  SOCKET_ERR(ret,"setsockopt bindtodevice");
  
  ret = setsockopt (tcp_listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));
  SOCKET_ERR(ret,"setsockopt reuseaddr");

  err = bind (tcp_listen_sd, reinterpret_cast<const sockaddr *> (& sa_serv),
	      sizeof (sa_serv));
  SOCKET_ERR (err, "bind");

  err = listen (tcp_listen_sd, 1024);
  SOCKET_ERR (err, "listen");

  //TCP IPv6 sockets creation done

  FD_ZERO(&rfds_orig);
  FD_SET(udp_listen_sd, &rfds_orig);
  FD_SET(tcp_listen_sd, &rfds_orig);

  printf ("Server ready. Listening to port '%d' on UDP and TCP.\n\n", PORT);

  for(;;){
    fd_set rfds = rfds_orig;

    ret = select(std::max(udp_listen_sd, tcp_listen_sd)+1, &rfds, 0, 0, 0);
    SOCKET_ERR(ret,"select");

    if (FD_ISSET(udp_listen_sd, &rfds)){
      udpreply(udp_listen_sd);
    }

    if (FD_ISSET(tcp_listen_sd, &rfds)){
      client_len = sizeof(sa_cli);
      int sd = accept (tcp_listen_sd,
	       reinterpret_cast<struct sockaddr *> (& sa_cli),
	       &client_len);
      SOCKET_ERR(sd,"accept"); //xxx not dieing when just connection abort      
      switch(fork()){
	case 0:
	  tcpreply(sd, &sa_cli, session);
	  return 0;
	  break;
      case -1:
	perror("fork");
	close(tcp_listen_sd);
	close(udp_listen_sd);
	return 1;
	break;
      default:
	break;
      }
    }
  }
  
  close(tcp_listen_sd);
  close(udp_listen_sd);
  return 0;

}
