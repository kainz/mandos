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
#include <string.h> 		/* strlen, rindex, strncmp, strcmp */

volatile bool quit_now = false;
bool debug = false;

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
  const char db[] = "--debug";
  char *basename = rindex(argv[0], '/');
  if(basename == NULL){
    basename = argv[0];
  } else {
    basename++;
  }

  char *program_name = malloc(strlen(basename) + sizeof(db));
  if (program_name == NULL){
    perror("argv[0]");
    return EXIT_FAILURE;
  }
    
  program_name[0] = '\0';
    
  for (int i = 1; i < argc; i++){
    if (not strncmp(argv[i], db, 5)){
      strcat(strcat(strcat(program_name, db ), "="), basename);
      if(not strcmp(argv[i], db) or not strcmp(argv[i], program_name)){
	debug = true;
      }
    }
  }
  free(program_name);

  if (debug){
    fprintf(stderr, "Starting %s\n", argv[0]);
  }
  if (debug){
    fprintf(stderr, "Storing current terminal attributes\n");
  }
  
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

  
  if (debug){
    fprintf(stderr, "Removing echo flag from terminal attributes\n");
  }
  
  t_new = t_old;
  t_new.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_new) != 0){
    perror("tcsetattr-echo");
    return EXIT_FAILURE;
  }

  if (debug){
    fprintf(stderr, "Waiting for input from stdin \n");
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

  if (debug){
    fprintf(stderr, "Restoring terminal attributes\n");
  }
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_old) != 0){
    perror("tcsetattr+echo");
  }

  if (debug){
    fprintf(stderr, "%s is exiting\n", argv[0]);
  }
  
  return status;
}
