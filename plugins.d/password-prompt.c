/*  -*- coding: utf-8; mode: c; mode: orgtbl -*- */
/*
 * Password-prompt - Read a password from the terminal and print it
 * 
 * Copyright © 2008-2019, 2021-2022 Teddy Hogeborn
 * Copyright © 2008-2019, 2021-2022 Björn Påhlsson
 * 
 * This file is part of Mandos.
 * 
 * Mandos is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Mandos is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Mandos.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Contact the authors at <mandos@recompile.se>.
 */

#define _GNU_SOURCE		/* vasprintf(),
				   program_invocation_short_name,
				   asprintf(), getline() */
#include <sys/types.h>		/* sig_atomic_t, pid_t */
#include <stdbool.h>		/* bool, false, true */
#include <argp.h>		/* argp_program_version,
				   argp_program_bug_address,
				   struct argp_option,
				   struct argp_state, argp_state_help,
				   ARGP_HELP_STD_HELP,
				   ARGP_HELP_EXIT_ERR,
				   ARGP_HELP_EXIT_OK, ARGP_HELP_USAGE,
				   argp_err_exit_status,
				   ARGP_ERR_UNKNOWN, argp_parse(),
				   ARGP_IN_ORDER, ARGP_NO_HELP */
#include <stdarg.h>		/* va_list, va_start(), vfprintf() */
#include <stdio.h>		/* vasprintf(), fprintf(), stderr,
				   vfprintf(), asprintf(), getline(),
				   stdin, feof(), clearerr(),
				   fputc() */
#include <errno.h>		/* program_invocation_short_name,
				   errno, ENOENT, error_t, ENOMEM,
				   EINVAL, EBADF, ENOTTY, EFAULT,
				   EFBIG, EIO, ENOSPC, EINTR */
#include <string.h>		/* strerror(), strrchr(), strcmp() */
#include <error.h>		/* error() */
#include <stdlib.h>		/* free(), realloc(), EXIT_SUCCESS,
				   EXIT_FAILURE, getenv() */
#include <unistd.h>		/* access(), R_OK, ssize_t, close(),
				   read(), STDIN_FILENO, write(),
				   STDOUT_FILENO */
#include <dirent.h>		/* struct dirent, scandir(),
				   alphasort() */
#include <inttypes.h>		/* uintmax_t, strtoumax() */
#include <iso646.h>		/* or, and, not */
#include <fcntl.h>		/* open(), O_RDONLY */
#include <stddef.h>		/* NULL, size_t */
#include <termios.h>		/* struct termios, tcgetattr(),
				   tcflag_t, ECHO, tcsetattr(),
				   TCSAFLUSH */
#include <signal.h>		/* struct sigaction, sigemptyset(),
				   sigaddset(), SIGINT, SIGHUP,
				   SIGTERM, SIG_IGN, SIG_DFL,
				   raise() */
#include <sysexits.h>		/* EX_OSERR, EX_USAGE, EX_UNAVAILABLE,
				   EX_IOERR, EX_OSFILE, EX_OK */

volatile sig_atomic_t quit_now = 0;
int signal_received;
bool debug = false;
const char *argp_program_version = "password-prompt " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";

/* Needed for conflict resolution */
const char plymouth_name[] = "plymouthd";

/* Function to use when printing errors */
__attribute__((format (gnu_printf, 3, 4)))
void error_plus(int status, int errnum, const char *formatstring,
		...){
  va_list ap;
  char *text;
  int ret;
  
  va_start(ap, formatstring);
  ret = vasprintf(&text, formatstring, ap);
  if(ret == -1){
    fprintf(stderr, "Mandos plugin %s: ",
	    program_invocation_short_name);
    vfprintf(stderr, formatstring, ap);
    fprintf(stderr, ": %s\n", strerror(errnum));
    error(status, errno, "vasprintf while printing error");
    return;
  }
  fprintf(stderr, "Mandos plugin ");
  error(status, errnum, "%s", text);
  free(text);
}

static void termination_handler(int signum){
  if(quit_now){
    return;
  }
  quit_now = 1;
  signal_received = signum;
}

bool conflict_detection(void){

  /* plymouth conflicts with password-prompt since both want to read
     from the terminal.  Password-prompt will exit if it detects
     plymouth since plymouth performs the same functionality.
   */
  if(access("/run/plymouth/pid", R_OK) == 0){
    return true;
  }
  
  __attribute__((nonnull))
  int is_plymouth(const struct dirent *proc_entry){
    int ret;
    int cl_fd;
    {
      uintmax_t proc_id;
      char *tmp;
      errno = 0;
      proc_id = strtoumax(proc_entry->d_name, &tmp, 10);
      
      if(errno != 0 or *tmp != '\0'
	 or proc_id != (uintmax_t)((pid_t)proc_id)){
	return 0;
      }
    }
    
    char *cmdline_filename;
    ret = asprintf(&cmdline_filename, "/proc/%s/cmdline",
		   proc_entry->d_name);
    if(ret == -1){
      error_plus(0, errno, "asprintf");
      return 0;
    }
    
    /* Open /proc/<pid>/cmdline */
    cl_fd = open(cmdline_filename, O_RDONLY);
    free(cmdline_filename);
    if(cl_fd == -1){
      if(errno != ENOENT){
	error_plus(0, errno, "open");
      }
      return 0;
    }
    
    char *cmdline = NULL;
    {
      size_t cmdline_len = 0;
      size_t cmdline_allocated = 0;
      char *tmp;
      const size_t blocksize = 1024;
      ssize_t sret;
      do {
	/* Allocate more space? */
	if(cmdline_len + blocksize + 1 > cmdline_allocated){
	  tmp = realloc(cmdline, cmdline_allocated + blocksize + 1);
	  if(tmp == NULL){
	    error_plus(0, errno, "realloc");
	    free(cmdline);
	    close(cl_fd);
	    return 0;
	  }
	  cmdline = tmp;
	  cmdline_allocated += blocksize;
	}
	
	/* Read data */
	sret = read(cl_fd, cmdline + cmdline_len,
		    cmdline_allocated - cmdline_len);
	if(sret == -1){
	  error_plus(0, errno, "read");
	  free(cmdline);
	  close(cl_fd);
	  return 0;
	}
	cmdline_len += (size_t)sret;
      } while(sret != 0);
      ret = close(cl_fd);
      if(ret == -1){
	error_plus(0, errno, "close");
	free(cmdline);
	return 0;
      }
      cmdline[cmdline_len] = '\0'; /* Make sure it is terminated */
    }
    /* we now have cmdline */
    
    /* get basename */
    char *cmdline_base = strrchr(cmdline, '/');
    if(cmdline_base != NULL){
      cmdline_base += 1;		/* skip the slash */
    } else {
      cmdline_base = cmdline;
    }
    
    if(strcmp(cmdline_base, plymouth_name) != 0){
      if(debug){
	fprintf(stderr, "\"%s\" is not \"%s\"\n", cmdline_base,
		plymouth_name);
      }
      free(cmdline);
      return 0;
    }
    if(debug){
      fprintf(stderr, "\"%s\" equals \"%s\"\n", cmdline_base,
	      plymouth_name);
    }
    free(cmdline);
    return 1;
  }
  
  struct dirent **direntries = NULL;
  int ret;
  ret = scandir("/proc", &direntries, is_plymouth, alphasort);
  if(ret == -1){
    error_plus(1, errno, "scandir");
  }
  {
    int i = ret;
    while(i--){
      free(direntries[i]);
    }
  }
  free(direntries);
  return ret > 0;
}


int main(int argc, char **argv){
  ssize_t sret;
  int ret;
  size_t n;
  struct termios t_new, t_old;
  char *buffer = NULL;
  char *prefix = NULL;
  char *prompt = NULL;
  int status = EXIT_SUCCESS;
  struct sigaction old_action,
    new_action = { .sa_handler = termination_handler,
		   .sa_flags = 0 };
  {
    struct argp_option options[] = {
      { .name = "prefix", .key = 'p',
	.arg = "PREFIX", .flags = 0,
	.doc = "Prefix shown before the prompt", .group = 2 },
      { .name = "prompt", .key = 129,
	.arg = "PROMPT", .flags = 0,
	.doc = "The prompt to show", .group = 2 },
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
    
    __attribute__((nonnull(3)))
    error_t parse_opt (int key, char *arg, struct argp_state *state){
      errno = 0;
      switch (key){
      case 'p':			/* --prefix */
	prefix = arg;
	break;
      case 128:			/* --debug */
	debug = true;
	break;
      case 129:			/* --prompt */
	prompt = arg;
	break;
	/*
	 * These reproduce what we would get without ARGP_NO_HELP
	 */
      case '?':			/* --help */
	argp_state_help(state, state->out_stream,
			(ARGP_HELP_STD_HELP | ARGP_HELP_EXIT_ERR)
			& ~(unsigned int)ARGP_HELP_EXIT_OK);
	__builtin_unreachable();
      case -3:			/* --usage */
	argp_state_help(state, state->out_stream,
			ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR);
	__builtin_unreachable();
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
      error_plus(0, errno, "argp_parse");
      return EX_OSERR;
    case EINVAL:
      return EX_USAGE;
    }
  }
  
  if(debug){
    fprintf(stderr, "Starting %s\n", argv[0]);
  }

  if(conflict_detection()){
    if(debug){
      fprintf(stderr, "Stopping %s because of conflict\n", argv[0]);
    }
    return EXIT_FAILURE;
  }
  
  if(debug){
    fprintf(stderr, "Storing current terminal attributes\n");
  }
  
  if(tcgetattr(STDIN_FILENO, &t_old) != 0){
    int e = errno;
    error_plus(0, errno, "tcgetattr");
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
    error_plus(0, errno, "sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGHUP);
  if(ret == -1){
    error_plus(0, errno, "sigaddset");
    return EX_OSERR;
  }
  ret = sigaddset(&new_action.sa_mask, SIGTERM);
  if(ret == -1){
    error_plus(0, errno, "sigaddset");
    return EX_OSERR;
  }
  /* Need to check if the handler is SIG_IGN before handling:
     | [[info:libc:Initial Signal Actions]] |
     | [[info:libc:Basic Signal Handling]]  |
  */
  ret = sigaction(SIGINT, NULL, &old_action);
  if(ret == -1){
    error_plus(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGINT, &new_action, NULL);
    if(ret == -1){
      error_plus(0, errno, "sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGHUP, NULL, &old_action);
  if(ret == -1){
    error_plus(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGHUP, &new_action, NULL);
    if(ret == -1){
      error_plus(0, errno, "sigaction");
      return EX_OSERR;
    }
  }
  ret = sigaction(SIGTERM, NULL, &old_action);
  if(ret == -1){
    error_plus(0, errno, "sigaction");
    return EX_OSERR;
  }
  if(old_action.sa_handler != SIG_IGN){
    ret = sigaction(SIGTERM, &new_action, NULL);
    if(ret == -1){
      error_plus(0, errno, "sigaction");
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
    error_plus(0, errno, "tcsetattr-echo");
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
    if(prompt != NULL){
      fprintf(stderr, "%s: ", prompt);
    } else {
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
	  error_plus(0, errno, "write");
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
	error_plus(0, errno, "close");
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
      if(errno != EINTR){
	if(not feof(stdin)){
	  error_plus(0, errno, "getline");
	  switch(e){
	  case EBADF:
	    status = EX_UNAVAILABLE;
	    break;
	  case EIO:
	  case EINVAL:
	  default:
	    status = EX_IOERR;
	    break;
	  }
	  break;
	} else {
	  clearerr(stdin);
	}
      }
    }
    /* if(sret == 0), then the only sensible thing to do is to retry
       to read from stdin */
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
    error_plus(0, errno, "tcsetattr+echo");
  }
  
  if(quit_now){
    sigemptyset(&old_action.sa_mask);
    old_action.sa_handler = SIG_DFL;
    ret = sigaction(signal_received, &old_action, NULL);
    if(ret == -1){
      error_plus(0, errno, "sigaction");
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
