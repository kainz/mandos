/*  -*- coding: utf-8 -*- */
/*
 * Passprompt - Read a password from the terminal and print it
 *
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
 * Contact the authors at <https://www.fukt.bsnet.se/~belorn/> and
 * <https://www.fukt.bsnet.se/~teddy/>.
 */

#define _GNU_SOURCE		/* getline() */

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
#include <stdlib.h>		/* EXIT_SUCCESS, EXIT_FAILURE,
				   getopt_long */
#include <stdio.h>		/* fprintf(), stderr, getline(),
				   stdin, feof(), perror(), fputc(),
				   stdout, getopt_long */
#include <errno.h>		/* errno, EINVAL */
#include <iso646.h>		/* or, not */
#include <stdbool.h>		/* bool, false, true */
#include <string.h> 		/* strlen, rindex, strncmp, strcmp */
#include <getopt.h>		/* getopt_long */

volatile bool quit_now = false;
bool debug = false;

void termination_handler(__attribute__((unused))int signum){
  quit_now = true;
}

int main(int argc, char **argv){
  ssize_t ret;
  size_t n;
  struct termios t_new, t_old;
  char *buffer = NULL;
  char *prefix = NULL;
  int status = EXIT_SUCCESS;
  struct sigaction old_action,
    new_action = { .sa_handler = termination_handler,
		   .sa_flags = 0 };

  while (true){
    static struct option long_options[] = {
      {"debug", no_argument, (int *)&debug, 1},
      {"prefix", required_argument, 0, 'p'},
      {0, 0, 0, 0} };

    int option_index = 0;
    ret = getopt_long (argc, argv, "p:", long_options, &option_index);

    if (ret == -1){
      break;
    }
      
    switch(ret){
    case 0:
      break;
    case 'p':
      prefix = optarg;
      break;
    default:
      fprintf(stderr, "bad arguments\n");
      exit(EXIT_FAILURE);
    }
  }
      
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
  sigaddset(&new_action.sa_mask, SIGHUP);
  sigaddset(&new_action.sa_mask, SIGTERM);
  sigaction(SIGINT, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction(SIGINT, &new_action, NULL);
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

    if(prefix){
      fprintf(stderr, "%s Password: ", prefix);
    } else {
      fprintf(stderr, "Password: ");
    }      
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
