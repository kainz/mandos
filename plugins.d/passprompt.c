#define _GNU_SOURCE		/* getline() */
#define _FORTIFY_SOURCE 2
#include <termios.h> 		/* struct termios, tcsetattr(),
				   TCSAFLUSH, tcgetattr(), ECHO */
#include <unistd.h>		/* struct termios, tcsetattr(),
				   STDIN_FILENO, TCSAFLUSH,
				   tcgetattr(), ECHO */
#include <signal.h>		/* sig_atomic_t, raise(), struct
				   sigaction, sigemptyset(),
				   sigaction(), sigaddset(), SIGINT,
				   SIGQUIT, SIGHUP, SIGTERM */
#include <stddef.h>		/* NULL, size_t */
#include <sys/types.h>		/* ssize_t */
#include <stdlib.h>		/* EXIT_SUCCESS, EXIT_FAILURE */
#include <stdio.h>		/* fprintf(), stderr, getline(),
				   stdin, feof(), perror(), fputc(),
				   stdout */
#include <errno.h>		/* errno, EINVAL */
#include <iso646.h>		/* or, not */
#include <stdbool.h>		/* bool, false, true */

volatile bool quit_now = false;

void termination_handler(int signum){
  quit_now = true;
}

int main(int argc, char **argv){
  ssize_t ret = -1;
  size_t n;
  struct termios t_new, t_old;
  char *buffer = NULL;
  int status = EXIT_SUCCESS;
  struct sigaction old_action,
    new_action = { .sa_handler = termination_handler,
		   .sa_flags = 0 };
  
  if (tcgetattr(STDIN_FILENO, &t_old) != 0){
    return EXIT_FAILURE;
  }
  
  sigemptyset(&new_action.sa_mask);
  sigaddset(&new_action.sa_mask, SIGINT);
  sigaddset(&new_action.sa_mask, SIGQUIT);
  sigaddset(&new_action.sa_mask, SIGHUP);
  sigaddset(&new_action.sa_mask, SIGTERM);
  sigaction(SIGINT, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction(SIGINT, &new_action, NULL);
  sigaction(SIGQUIT, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction(SIGQUIT, &new_action, NULL);
  sigaction(SIGHUP, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction(SIGHUP, &new_action, NULL);
  sigaction(SIGTERM, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction(SIGTERM, &new_action, NULL);
  
  t_new = t_old;
  t_new.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_new) != 0){
    perror("tcsetattr-echo");
    return EXIT_FAILURE;
  }
  
  while(true){
    if (quit_now){
      status = EXIT_FAILURE;
      break;
    }
    fprintf(stderr, "Password: ");
    ret = getline(&buffer, &n, stdin);
    if (ret > 0){
      fprintf(stdout, "%s", buffer);
      status = EXIT_SUCCESS;
      break;
    }
    // ret == 0 makes no other sence than to retry to read from stdin
    if (ret < 0){
      if (errno != EINTR and not feof(stdin)){
	perror("getline");
	status = EXIT_FAILURE;
	break;
      }
    }
    fputc('\n', stderr);
  }

  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_old) != 0){
    perror("tcsetattr+echo");
  }
  
  return status;
}
