extern "C" {
#include <sys/types.h>		// getaddrinfo, gai_strerror, socket, inet_pton
				// connect
#include <sys/socket.h>		// getaddrinfo, gai_strerror, socket, inet_pton
				// connect
#include <unistd.h>		// close, STDIN_FILENO, STDOUT_FILENO
#include <netdb.h>		// getaddrinfo, gai_strerror
#include <arpa/inet.h>		// inet_pton
#include <sys/select.h> 	// select
#include <gnutls/gnutls.h>
#include <sys/ioctl.h> 		// ioctl, ifreq, SIOCGIFFLAGS, IFF_UP, SIOCSIFFLAGS
#include <net/if.h> 		// ioctl, ifreq, SIOCGIFFLAGS, IFF_UP, SIOCSIFFLAGS
#include <termios.h> 		// struct termios, tcsetattr, tcgetattr, TCSAFLUSH, ECHO
}

#include <cerrno>		// perror
#include <cstring> 		// memset
#include <string> 		// std::string, std::getline
#include <iostream> 		// cin, cout, cerr
#include <ostream> 		// <<

#define SOCKET_ERR(err,s) if(err<0) {perror(s); status = 1; goto quit;}
#define PORT 49001

#ifndef CERT_ROOT
#define CERT_ROOT "/conf/conf.d/cryptkeyreq/"
#endif
#define CERTFILE CERT_ROOT "client-cert.pem"
#define KEYFILE CERT_ROOT "client-key.pem"
#define CAFILE CERT_ROOT "ca.pem"

gnutls_certificate_credentials_t x509_cred;

gnutls_session_t
initgnutls(){
  gnutls_session_t session;

#ifdef DEBUG
  std::cerr << "Initiate certificates\n";
#endif

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
  int udp_sd, tcp_sd, ret;
  char buffer[4096];
  struct sockaddr_in6 to;
  struct sockaddr_in6 from;
  gnutls_session_t session;
  fd_set rfds_orig;
  struct timeval timeout;

  struct termios t_old, t_new;
  int status = 0;
  
  if (tcgetattr (STDIN_FILENO, &t_old) != 0){
    return 1;
  }
  
  session = initgnutls ();

#ifdef DEBUG
  std::cerr << "Open ipv6 UDP\n";
#endif

  udp_sd = socket(PF_INET6, SOCK_DGRAM, 0);
  SOCKET_ERR(udp_sd,"socket");
  
#ifdef DEBUG
  std::cerr << "Open socket with socket nr: " << udp_sd << '\n';
#endif
  
  {
    int flag = 1;
    ret = setsockopt(udp_sd, SOL_SOCKET, SO_BROADCAST, & flag, sizeof(flag));
    SOCKET_ERR(ret,"setsockopt broadcast");
  }

  ret = setsockopt(udp_sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
  SOCKET_ERR(ret,"setsockopt bindtodevice");

  memset (&to, '\0', sizeof (to));
  to.sin6_family = AF_INET6;
  ret = inet_pton(AF_INET6, "ff02::1" , &to.sin6_addr);
  SOCKET_ERR(ret,"inet_pton");
  to.sin6_port = htons (PORT);	// Server Port number

  struct ifreq network;

  strcpy(network.ifr_name, "eth0");

  ret = ioctl(udp_sd, SIOCGIFFLAGS, &network);
  SOCKET_ERR(ret,"ioctl SIOCGIFFLAGS");

  network.ifr_flags |= IFF_UP;

  ret = ioctl(udp_sd, SIOCSIFFLAGS, &network);
  SOCKET_ERR(ret,"ioctl SIOCSIFFLAGS");
    
  FD_ZERO(&rfds_orig);
  FD_SET(udp_sd, &rfds_orig);
  FD_SET(STDIN_FILENO, &rfds_orig);
  
  t_new = t_old;
  t_new.c_lflag &= ~ECHO;
  if (tcsetattr (STDIN_FILENO, TCSAFLUSH, &t_new) != 0){
    return 1;
  }
  
  for(;;){
    for(;;){

#ifdef DEBUG
      std::cerr << "Sending Marco on UDP\n";
#endif
      ret = sendto(udp_sd, "Marco", 5, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
      if (ret < 0){
	perror("sendto");
      }
      
      fd_set rfds = rfds_orig;
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      
      std::cerr << "Password: ";
      
      ret = select(udp_sd+1, &rfds, 0, 0, & timeout);
      SOCKET_ERR(udp_sd,"select");
      
      if (ret){
	if (FD_ISSET(STDIN_FILENO, &rfds)){
	  std::string buffer;
	  std::getline(std::cin, buffer);
	  std::cerr << '\n';
	  std::cout << buffer;
	  goto quit;
	}
	
	socklen_t from_len = sizeof(from);
	ret = recvfrom(udp_sd,buffer,512,0, reinterpret_cast<sockaddr *>(& from),
		       & from_len);
	SOCKET_ERR(ret,"recv");
	
	if (strncmp(buffer,"Polo", 4) == 0){
	  break;
	}
      }
      std::cerr << '\r';
    }
    
    
    tcp_sd = socket(PF_INET6, SOCK_STREAM, 0);
    SOCKET_ERR(tcp_sd,"socket");
    
    setsockopt(tcp_sd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
    SOCKET_ERR(ret,"setsockopt bindtodevice");
    
    memset(&to,0,sizeof(to));
    to.sin6_family = from.sin6_family;
    to.sin6_port   = from.sin6_port;
    to.sin6_addr   = from.sin6_addr;
    to.sin6_scope_id   = from.sin6_scope_id;
    
    ret = connect(tcp_sd,reinterpret_cast<struct sockaddr *>(&to),sizeof(to));
    if (ret < 0){
      perror("connect");
      continue;
    }
    
    gnutls_transport_set_ptr (session, reinterpret_cast<gnutls_transport_ptr_t> (tcp_sd));
    
    ret = gnutls_handshake (session);
    
    if (ret < 0)
      {
	std::cerr << "\n*** Handshake failed ***\n";
	gnutls_perror (ret);
	continue;
      }
    
    //retrive password
    ret = gnutls_record_recv (session, buffer, sizeof(buffer));
    
    write(STDOUT_FILENO,buffer,ret);
    
    //shutdown procedure
    gnutls_bye (session, GNUTLS_SHUT_RDWR);
    close(tcp_sd);
    gnutls_deinit (session);
    gnutls_certificate_free_credentials (x509_cred);
    gnutls_global_deinit ();
    break;
  }
  close(udp_sd);

 quit:
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &t_old);
  return status;
}
