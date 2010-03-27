/*  -*- coding: utf-8; mode: c; mode: orgtbl -*- */
/*
 * Password-prompt - Read a password from the terminal and print it
 * 
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

#define _GNU_SOURCE		/* getline() */

#include <termios.h> 		/* struct termios, tcsetattr(),
				   TCSAFLUSH, tcgetattr(), ECHO */
#include <unistd.h>		/* struct termios, tcsetattr(),
				   STDIN_FILENO, TCSAFLUSH,
				   tcgetattr(), ECHO */
#include <signal.h>		/* sig_atomic_t, raise(), struct
				   sigaction, sigemptyset(),
				   sigaction(), sigaddset(), SIGINT,
				   SIGQUIT, SIGHUP, SIGTERM,
				   raise() */
#include <stddef.h>		/* NULL, size_t, ssize_t */
#include <sys/types.h>		/* ssize_t */
#include <stdlib.h>		/* EXIT_SUCCESS, EXIT_FAILURE,
				   getenv() */
#include <stdio.h>		/* fprintf(), stderr, getline(),
				   stdin, feof(), perror(), fputc()
				*/
#include <errno.h>		/* errno, EBADF, ENOTTY, EINVAL,
				   EFAULT, EFBIG, EIO, ENOSPC, EINTR
				*/
#include <iso646.h>		/* or, not */
#include <stdbool.h>		/* bool, false, true */
#include <string.h> 		/* strlen, rindex */
#include <argp.h>		/* struct argp_option, struct
				   argp_state, struct argp,
				   argp_parse(), error_t,
				   ARGP_KEY_ARG, ARGP_KEY_END,
				   ARGP_ERR_UNKNOWN */
#include <sysexits.h>		/* EX_SOFTWARE, EX_OSERR,
				   EX_UNAVAILABLE, EX_IOERR, EX_OK */

volatile sig_atomic_t quit_now = 0;
int signal_received;
bool debug = false;
const char *argp_program_version = "password-prompt " VERSION;
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";

static void termination_handler(int signum){
  if(quit_now){
    return;
  }
  quit_now = 1;
  signal_received = signum;
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
	.doc = "Prefix shown before the prompt", .group = 2 },
      { .name = "debug", .key = 128,
	.doc = "Debug mode", .group = 3 },
      /*
       * These reproduce what we would get without ARGP_NO_HELP
       */
      { .name = "help", .key = '?',
	.doc = "Give this help list", .group = -1 },
      { .name = "usage", .key = -3,
	.doc = "Give a short usage message", .group = -1 },
      { .name = "version", .key = 'V',
	.doc = "Print program version", .group = -1 },
      { .name = NULL }
    };
    
    error_t parse_opt (int key, char *arg, struct argp_state *state){
      errno = 0;
      switch (key){
      case 'p':
	prefix = arg;
	break;
      case 128:
	debug = true;
	break;
	/*
	 * These reproduce what we would get without ARGP_NO_HELP
	 */
      case '?':			/* --help */
	argp_state_help(state, state->out_stream,
			(ARGP_HELP_STD_HELP | ARGP_HELP_EXIT_ERR)
			& ~(unsigned int)ARGP_HELP_EXIT_OK);
      case -3:			/* --usage */
	argp_state_help(state, state->out_stream,
			ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR);
      case 'V':			/* --version */
	fprintf(state->out_stream, "%s\n", argp_program_version);
	exit(argp_err_exit_status);
	break;
      default:
	return ARGP_ERR_UNKNOWN;
      }
      return errno;
    }
    
    struct argp argp = { .options = options, .parser = parse_opt,
			 .args_doc = "",
			 .doc = "Mandos password-prompt -- Read and"
			 " output a password" };
    ret = argp_parse(&argp, argc, argv,
		     ARGP_IN_ORDER | ARGP_NO_HELP, NULL, NULL);
    switch(ret){
    case 0:
      break;
    case ENOMEM:
    default:
      errno = ret;
      perror("argp_parse");
      return EX_OSERR;
    case EINVAL:
      return EX_USAGE;
    }
  }
  
  if(debug){
    fprintf(stderr, "Starting %s\n", argv[0]);
  }
  if(debug){
    fprintf(stderr, "Storing current terminal attributes\n");
  }
  
  if(tcgetattr(STDIN_FILENO, &t_old) != 0){
    int e = errno;
    perror("tcgetattr");
    switch(e){
    case EBADF:
    case ENOTTY:
      return EX_UNAVAILABLE;
    default:
      return EX_OSERR;
    }
  }
  
  sigemptyset(&new_action.sa_mask);
  ret = sigaddset(&new_action.sa_mask, SIGINT);
  if(ret == -1){
    perror("sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGHUP);
  if(ret == -1){
    perror("sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGTERM);
  if(ret == -1){
    perror("sigaddset");
    return EX_OSERR;
  }
  /* Need to check if the handler is SIG_IGN before handling:
     | [[info:libc:Initial Signal Actions]] |
     | [[info:libc:Basic Signal Handling]]  |
  */
  ret = sigaction(SIGINT, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_action);
  if(ret == -1){
    perror("sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &new_action, NULL);
    if(ret == -1){
      perror("sigaction");
      return EX_OSERR;
    }
  }
  
  
  if(debug){
    fprintf(stderr, "Removing echo flag from terminal attributes\n");
  }
  
  t_new = t_old;
  t_new.c_lflag &= ~(tcflag_t)ECHO;
  if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_new) != 0){
    int e = errno;
    perror("tcsetattr-echo");
    switch(e){
    case EBADF:
    case ENOTTY:
      return EX_UNAVAILABLE;
    case EINVAL:
    default:
      return EX_OSERR;
    }
  }
  
  if(debug){
    fprintf(stderr, "Waiting for input from stdin \n");
  }
  while(true){
    if(quit_now){
      if(debug){
	fprintf(stderr, "Interrupted by signal, exiting.\n");
      }
      status = EXIT_FAILURE;
      break;
    }

    if(prefix){
      fprintf(stderr, "%s ", prefix);
    }
    {
      const char *cryptsource = getenv("CRYPTTAB_SOURCE");
      const char *crypttarget = getenv("CRYPTTAB_NAME");
      /* Before cryptsetup 1.1.0~rc2 */
      if(cryptsource == NULL){
	cryptsource = getenv("cryptsource");
      }
      if(crypttarget == NULL){
	crypttarget = getenv("crypttarget");
      }
      const char *const prompt1 = "Unlocking the disk";
      const char *const prompt2 = "Enter passphrase";
      if(cryptsource == NULL){
	if(crypttarget == NULL){
	  fprintf(stderr, "%s to unlock the disk: ", prompt2);
	} else {
	  fprintf(stderr, "%s (%s)\n%s: ", prompt1, crypttarget,
		  prompt2);
	}
      } else {
	if(crypttarget == NULL){
	  fprintf(stderr, "%s %s\n%s: ", prompt1, cryptsource,
		  prompt2);
	} else {
	  fprintf(stderr, "%s %s (%s)\n%s: ", prompt1, cryptsource,
		  crypttarget, prompt2);
	}
      }
    }
    ret = getline(&buffer, &n, stdin);
    if(ret > 0){
      status = EXIT_SUCCESS;
      /* Make n = data size instead of allocated buffer size */
      n = (size_t)ret;
      /* Strip final newline */
      if(n > 0 and buffer[n-1] == '\n'){
	buffer[n-1] = '\0';	/* not strictly necessary */
	n--;
      }
      size_t written = 0;
      while(written < n){
	ret = write(STDOUT_FILENO, buffer + written, n - written);
	if(ret < 0){
	  int e = errno;
	  perror("write");
	  switch(e){
	  case EBADF:
	  case EFAULT:
	  case EINVAL:
	  case EFBIG:
	  case EIO:
	  case ENOSPC:
	  default:
	    status = EX_IOERR;
	    break;
	  case EINTR:
	    status = EXIT_FAILURE;
	    break;
	  }
	  break;
	}
	written += (size_t)ret;
      }
      ret = close(STDOUT_FILENO);
      if(ret == -1){
	int e = errno;
	perror("close");
	switch(e){
	case EBADF:
	  status = EX_OSFILE;
	  break;
	case EIO:
	default:
	  status = EX_IOERR;
	  break;
	}
      }
      break;
    }
    if(ret < 0){
      int e = errno;
      if(errno != EINTR and not feof(stdin)){
	perror("getline");
	switch(e){
	case EBADF:
	  status = EX_UNAVAILABLE;
	case EIO:
	case EINVAL:
	default:
	  status = EX_IOERR;
	  break;
	}
	break;
      }
    }
    /* if(ret == 0), then the only sensible thing to do is to retry to
       read from stdin */
    fputc('\n', stderr);
    if(debug and not quit_now){
      /* If quit_now is nonzero, we were interrupted by a signal, and
	 will print that later, so no need to show this too. */
      fprintf(stderr, "getline() returned 0, retrying.\n");
    }
  }
  
  free(buffer);
  
  if(debug){
    fprintf(stderr, "Restoring terminal attributes\n");
  }
  if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_old) != 0){
    perror("tcsetattr+echo");
  }
  
  if(quit_now){
    sigemptyset(&old_action.sa_mask);
    old_action.sa_handler = SIG_DFL;
    ret = sigaction(signal_received, &old_action, NULL);
    if(ret == -1){
      perror("sigaction");
    }
    raise(signal_received);
  }
  
  if(debug){
    fprintf(stderr, "%s is exiting with status %d\n", argv[0],
	    status);
  }
  if(status == EXIT_SUCCESS or status == EX_OK){
    fputc('\n', stderr);
  }
  
  return status;
}
