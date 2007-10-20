extern "C" {
#include <sys/types.h>		// getaddrinfo, gai_strerror, socket, inet_pton
				// connect
#include <sys/socket.h>		// getaddrinfo, gai_strerror, socket, inet_pton
				// connect
#include <unistd.h>		// close
#include <netdb.h>		// getaddrinfo, gai_strerror
#include <arpa/inet.h>		// inet_pton
#include <sys/select.h> 	// select
#include <gnutls/gnutls.h>
}

#include <cstdio>		// fprintf
#include <cerrno>		// perror
#include <cstring> 		// memset

#define SOCKET_ERR(err,s) if(err<0) {perror(s);return(1);}
#define PORT 49001
#define CERTFILE "client-cert.pem"
#define KEYFILE "client-key.pem"
#define CAFILE "ca.pem"

gnutls_certificate_credentials_t x509_cred;

gnutls_session_t
initgnutls(){
  gnutls_session_t session;

  gnutls_global_init ();

  /* X509 stuff */
  gnutls_certificate_allocate_credentials (&x509_cred);
  gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
  gnutls_certificate_set_x509_key_file (x509_cred, CERTFILE, KEYFILE,
					GNUTLS_X509_FMT_PEM);

  //Gnutls stuff
  gnutls_init (&session, GNUTLS_CLIENT);
  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  return session;
}


int main (){
  int sd, ret;
  char buffer[512];
  struct sockaddr_in6 to;
  struct sockaddr_in6 from;
  gnutls_session_t session;
  fd_set rfds_orig;
  struct timeval timeout;

  session = initgnutls ();

  sd = socket(PF_INET6, SOCK_DGRAM, 0);
  SOCKET_ERR(sd,"socket");
 
  {
    int flag = 1;
    ret = setsockopt(sd, SOL_SOCKET, SO_BROADCAST, & flag, sizeof(flag));
    SOCKET_ERR(ret,"setsockopt broadcast");
  }

  setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
  SOCKET_ERR(ret,"setsockopt bindtodevice");

  memset (&to, '\0', sizeof (to));
  to.sin6_family = AF_INET6;
  ret = inet_pton(AF_INET6, "ff02::1" , &to.sin6_addr);
  SOCKET_ERR(ret,"setsockopt bindtodevice");
  to.sin6_port = htons (PORT);	// Server Port number

  FD_ZERO(&rfds_orig);
  FD_SET(sd, &rfds_orig);

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;


  for(;;){
    sendto(sd, "Marco", 5, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));

    fd_set rfds = rfds_orig;

    ret = select(sd+1, &rfds, 0, 0, & timeout);
    SOCKET_ERR(sd,"select");

    if (ret){
      socklen_t from_len = sizeof(from);
      ret = recvfrom(sd,buffer,512,0, reinterpret_cast<sockaddr *>(& from),
		     & from_len);
      SOCKET_ERR(ret,"recv");

      if (strncmp(buffer,"Polo", 4) == 0){
	break;
      }
    }
  }

  write(1,buffer,ret);
  write(1,"\n",1);

  //shutdown procedure
  close(sd);

  sleep(1);

  sd = socket(PF_INET6, SOCK_STREAM, 0);
  SOCKET_ERR(sd,"socket");

  setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
  SOCKET_ERR(ret,"setsockopt bindtodevice");

  memset(&to,0,sizeof(to));
  to.sin6_family = from.sin6_family;
  to.sin6_port   = from.sin6_port;
  to.sin6_addr   = from.sin6_addr;
  to.sin6_scope_id   = from.sin6_scope_id;

  ret = connect(sd,reinterpret_cast<struct sockaddr *>(&to),sizeof(to));
  SOCKET_ERR(ret,"connect");

  gnutls_transport_set_ptr (session, reinterpret_cast<gnutls_transport_ptr_t> (sd));

  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      fprintf (stderr, "*** Handshake failed\n");
      gnutls_perror (ret);
      return 1;
    }
  printf ("- Handshake was completed\n");

  //message to be seent
  gnutls_record_send (session, "The secret message is \"squeamish ossifrage\"\n", 44);

  //shutdown procedure
  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close(sd);
  gnutls_deinit (session);
  gnutls_certificate_free_credentials (x509_cred);
  gnutls_global_deinit ();

  close(sd);

  return 0;
}
