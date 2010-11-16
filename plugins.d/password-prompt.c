/*  -*- coding: utf-8; mode: c; mode: orgtbl -*- */
/*
 * Password-prompt - Read a password from the terminal and print it
 * 
 * Copyright © 2008-2010 Teddy Hogeborn
 * Copyright © 2008-2010 Björn Påhlsson
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

#define _GNU_SOURCE		/* getline(), asprintf() */

#include <termios.h> 		/* struct termios, tcsetattr(),
				   TCSAFLUSH, tcgetattr(), ECHO */
#include <unistd.h>		/* struct termios, tcsetattr(),
				   STDIN_FILENO, TCSAFLUSH,
				   tcgetattr(), ECHO, readlink() */
#include <signal.h>		/* sig_atomic_t, raise(), struct
				   sigaction, sigemptyset(),
				   sigaction(), sigaddset(), SIGINT,
				   SIGQUIT, SIGHUP, SIGTERM,
				   raise() */
#include <stddef.h>		/* NULL, size_t, ssize_t */
#include <sys/types.h>		/* ssize_t, struct dirent, pid_t, ssize_t */
#include <stdlib.h>		/* EXIT_SUCCESS, EXIT_FAILURE,
				   getenv(), free() */
#include <dirent.h>		/* scandir(), alphasort() */
#include <stdio.h>		/* fprintf(), stderr, getline(),
				   stdin, feof(), fputc()
				*/
#include <errno.h>		/* errno, EBADF, ENOTTY, EINVAL,
				   EFAULT, EFBIG, EIO, ENOSPC, EINTR
				*/
#include <error.h>		/* error() */
#include <iso646.h>		/* or, not */
#include <stdbool.h>		/* bool, false, true */
#include <inttypes.h>		/* strtoumax() */
#include <sys/stat.h> 		/* struct stat, lstat() */
#include <string.h> 		/* strlen, rindex, memcmp */
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

/* Needed for conflic resolution */
const char plymouthd_path[] = "/sbin/plymouth";


static void termination_handler(int signum){
  if(quit_now){
    return;
  }
  quit_now = 1;
  signal_received = signum;
}

bool conflict_detection(void){

  /* plymouth conflicts with password-promt since both want to control the
     associated terminal. Password-prompt exit since plymouth perferms the same
     functionallity.
   */
  int is_plymouth(const struct dirent *proc_entry){
    int ret;
    {
      uintmax_t maxvalue;
      char *tmp;
      errno = 0;
      maxvalue = strtoumax(proc_entry->d_name, &tmp, 10);
      
      if(errno != 0 or *tmp != '\0'
	 or maxvalue != (uintmax_t)((pid_t)maxvalue)){
	return 0;
      }
    }
    char exe_target[sizeof(plymouthd_path)];
    char *exe_link;
    ret = asprintf(&exe_link, "/proc/%s/exe", proc_entry->d_name);
    if(ret == -1){
      error(0, errno, "asprintf");
      return 0;
    }
  
    struct stat exe_stat;
    ret = lstat(exe_link, &exe_stat);
    if(ret == -1){
      free(exe_link);
      if(errno != ENOENT){
	error(0, errno, "lstat");
      }
      return 0;
    }
  
    if(not S_ISLNK(exe_stat.st_mode)
       or exe_stat.st_uid != 0
       or exe_stat.st_gid != 0){
      free(exe_link);
      return 0;
    }
  
    ssize_t sret = readlink(exe_link, exe_target, sizeof(exe_target));
    free(exe_link);
    if((sret != (ssize_t)sizeof(plymouthd_path)-1) or
       (memcmp(plymouthd_path, exe_target,
	       sizeof(plymouthd_path)-1) != 0)){
      return 0;
    }
    return 1;
  }

  struct dirent **direntries;
  int ret;
  ret = scandir("/proc", &direntries, is_plymouth, alphasort);
  if (ret == -1){
    error(1, errno, "scandir");
  }
  if (ret < 0){
    return 1;
  } else {
    return 0;
  }
}


int main(int argc, char **argv){
  ssize_t sret;
  int ret;
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
      error(0, errno, "argp_parse");
      return EX_OSERR;
    case EINVAL:
      return EX_USAGE;
    }
  }
  
  if(debug){
    fprintf(stderr, "Starting %s\n", argv[0]);
  }

  if (conflict_detection()){
    if(debug){
      fprintf(stderr, "Stopping %s because of conflict", argv[0]);
    }
    return EXIT_FAILURE;
  }
  
  if(debug){
    fprintf(stderr, "Storing current terminal attributes\n");
  }
  
  if(tcgetattr(STDIN_FILENO, &t_old) != 0){
    int e = errno;
    error(0, errno, "tcgetattr");
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
    error(0, errno, "sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGHUP);
  if(ret == -1){
    error(0, errno, "sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGTERM);
  if(ret == -1){
    error(0, errno, "sigaddset");
    return EX_OSERR;
  }
  /* Need to check if the handler is SIG_IGN before handling:
     | [[info:libc:Initial Signal Actions]] |
     | [[info:libc:Basic Signal Handling]]  |
  */
  ret = sigaction(SIGINT, NULL, &old_action);
  if(ret == -1){
    error(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &new_action, NULL);
    if(ret == -1){
      error(0, errno, "sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_action);
  if(ret == -1){
    error(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &new_action, NULL);
    if(ret == -1){
      error(0, errno, "sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_action);
  if(ret == -1){
    error(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &new_action, NULL);
    if(ret == -1){
      error(0, errno, "sigaction");
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
    error(0, errno, "tcsetattr-echo");
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
    sret = getline(&buffer, &n, stdin);
    if(sret > 0){
      status = EXIT_SUCCESS;
      /* Make n = data size instead of allocated buffer size */
      n = (size_t)sret;
      /* Strip final newline */
      if(n > 0 and buffer[n-1] == '\n'){
	buffer[n-1] = '\0';	/* not strictly necessary */
	n--;
      }
      size_t written = 0;
      while(written < n){
	sret = write(STDOUT_FILENO, buffer + written, n - written);
	if(sret < 0){
	  int e = errno;
	  error(0, errno, "write");
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
	written += (size_t)sret;
      }
      sret = close(STDOUT_FILENO);
      if(sret == -1){
	int e = errno;
	error(0, errno, "close");
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
    if(sret < 0){
      int e = errno;
      if(errno != EINTR and not feof(stdin)){
	error(0, errno, "getline");
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
    /* if(sret == 0), then the only sensible thing to do is to retry to
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
    error(0, errno, "tcsetattr+echo");
  }
  
  if(quit_now){
    sigemptyset(&old_action.sa_mask);
    old_action.sa_handler = SIG_DFL;
    ret = sigaction(signal_received, &old_action, NULL);
    if(ret == -1){
      error(0, errno, "sigaction");
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
