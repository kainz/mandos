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
#include <stddef.h>		/* NULL, size_t, ssize_t */
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
#include <argp.h>		/* struct argp_option, struct
				   argp_state, struct argp,
				   argp_parse(), error_t,
				   ARGP_KEY_ARG, ARGP_KEY_END,
				   ARGP_ERR_UNKNOWN */

volatile bool quit_now = false;
bool debug = false;
const char *argp_program_version = "passprompt 0.9";
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";

static void termination_handler(__attribute__((unused))int signum){
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
  {
    struct argp_option options[] = {
      { .name = "prefix", .key = 'p',
	.arg = "PREFIX", .flags = 0,
	.doc = "Prefix used before the passprompt", .group = 2 },
      { .name = "debug", .key = 128,
	.doc = "Debug mode", .group = 3 },
      { .name = NULL }
    };
  
    error_t parse_opt (int key, char *arg, struct argp_state *state) {
      /* Get the INPUT argument from `argp_parse', which we know is a
	 pointer to our plugin list pointer. */
      switch (key) {
      case 'p':
	prefix = arg;
	break;
      case 128:
	debug = true;
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
			 .doc = "Mandos Passprompt -- Provides a passprompt" };
    ret = argp_parse (&argp, argc, argv, 0, 0, NULL);
    if (ret == ARGP_ERR_UNKNOWN){
      perror("argp_parse");
      return EXIT_FAILURE;
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
  ret = sigaction(SIGINT, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if (old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EXIT_FAILURE;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if (old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EXIT_FAILURE;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EXIT_FAILURE;
  }
  if (old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EXIT_FAILURE;
    }
  }
  
  
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
    if (ret < 0){
      if (errno != EINTR and not feof(stdin)){
	perror("getline");
	status = EXIT_FAILURE;
	break;
      }
    }
    /* if(ret == 0), then the only sensible thing to do is to retry to
       read from stdin */
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
