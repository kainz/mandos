/*  -*- coding: utf-8 -*- */
/*
 * Splashy - Read a password from splashy and output it
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

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY(), asprintf() */
#include <signal.h>		/* sig_atomic_t, struct sigaction,
				   sigemptyset(), sigaddset(), SIGINT,
				   SIGHUP, SIGTERM, sigaction,
				   SIG_IGN, kill(), SIGKILL */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* getenv() */
#include <stdio.h>		/* asprintf() */
#include <stdlib.h>		/* EXIT_FAILURE, free(),
				   EXIT_SUCCESS */
#include <sys/types.h>		/* pid_t, DIR, struct dirent,
				   ssize_t */
#include <dirent.h>		/* opendir(), readdir(), closedir() */
#include <inttypes.h>		/* intmax_t, strtoimax() */
#include <sys/stat.h>		/* struct stat, lstat(), S_ISLNK */
#include <iso646.h>		/* not, or, and */
#include <unistd.h>		/* readlink(), fork(), execl(),
				   sleep(), dup2() STDERR_FILENO,
				   STDOUT_FILENO, _exit(),
				   pause() */
#include <string.h>		/* memcmp() */
#include <errno.h>		/* errno, EACCES, ENOTDIR, ELOOP,
				   ENOENT, ENAMETOOLONG, EMFILE,
				   ENFILE, ENOMEM, ENOEXEC, EINVAL,
				   E2BIG, EFAULT, EIO, ETXTBSY,
				   EISDIR, ELIBBAD, EPERM, EINTR,
				   ECHILD */
#include <error.h>		/* error() */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS() */
#include <sysexits.h>		/* EX_OSERR, EX_OSFILE,
				   EX_UNAVAILABLE */

sig_atomic_t interrupted_by_signal = 0;
int signal_received;

static void termination_handler(int signum){
  if(interrupted_by_signal){
    return;
  }
  interrupted_by_signal = 1;
  signal_received = signum;
}

int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  int ret = 0;
  char *prompt = NULL;
  DIR *proc_dir = NULL;
  pid_t splashy_pid = 0;
  pid_t splashy_command_pid = 0;
  int exitstatus = EXIT_FAILURE;
  
  /* Create prompt string */
  {
    const char *const cryptsource = getenv("cryptsource");
    const char *const crypttarget = getenv("crypttarget");
    const char *const prompt_start = "getpass "
      "Enter passphrase to unlock the disk";
    
    if(cryptsource == NULL){
      if(crypttarget == NULL){
	ret = asprintf(&prompt, "%s: ", prompt_start);
      } else {
	ret = asprintf(&prompt, "%s (%s): ", prompt_start,
		       crypttarget);
      }
    } else {
      if(crypttarget == NULL){
	ret = asprintf(&prompt, "%s %s: ", prompt_start, cryptsource);
      } else {
	ret = asprintf(&prompt, "%s %s (%s): ", prompt_start,
		       cryptsource, crypttarget);
      }
    }
    if(ret == -1){
      prompt = NULL;
      exitstatus = EX_OSERR;
      goto failure;
    }
  }
  
  /* Find splashy process */
  {
    const char splashy_name[] = "/sbin/splashy";
    proc_dir = opendir("/proc");
    if(proc_dir == NULL){
      int e = errno;
      error(0, errno, "opendir");
      switch(e){
      case EACCES:
      case ENOTDIR:
      case ELOOP:
      case ENOENT:
      default:
	exitstatus = EX_OSFILE;
	break;
      case ENAMETOOLONG:
      case EMFILE:
      case ENFILE:
      case ENOMEM:
	exitstatus = EX_OSERR;
	break;
      }
      goto failure;
    }
    for(struct dirent *proc_ent = readdir(proc_dir);
	proc_ent != NULL;
	proc_ent = readdir(proc_dir)){
      pid_t pid;
      {
	intmax_t tmpmax;
	char *tmp;
	errno = 0;
	tmpmax = strtoimax(proc_ent->d_name, &tmp, 10);
	if(errno != 0 or tmp == proc_ent->d_name or *tmp != '\0'
	   or tmpmax != (pid_t)tmpmax){
	  /* Not a process */
	  continue;
	}
	pid = (pid_t)tmpmax;
      }
      /* Find the executable name by doing readlink() on the
	 /proc/<pid>/exe link */
      char exe_target[sizeof(splashy_name)];
      ssize_t sret;
      {
	char *exe_link;
	ret = asprintf(&exe_link, "/proc/%s/exe", proc_ent->d_name);
	if(ret == -1){
	  error(0, errno, "asprintf");
	  exitstatus = EX_OSERR;
	  goto failure;
	}
	
	/* Check that it refers to a symlink owned by root:root */
	struct stat exe_stat;
	ret = lstat(exe_link, &exe_stat);
	if(ret == -1){
	  if(errno == ENOENT){
	    free(exe_link);
	    continue;
	  }
	  int e = errno;
	  error(0, errno, "lstat");
	  free(exe_link);
	  switch(e){
	  case EACCES:
	  case ENOTDIR:
	  case ELOOP:
	  default:
	    exitstatus = EX_OSFILE;
	    break;
	  case ENAMETOOLONG:
	    exitstatus = EX_OSERR;
	    break;
	  }
	  goto failure;
	}
	if(not S_ISLNK(exe_stat.st_mode)
	   or exe_stat.st_uid != 0
	   or exe_stat.st_gid != 0){
	  free(exe_link);
	  continue;
	}
	
	sret = readlink(exe_link, exe_target, sizeof(exe_target));
	free(exe_link);
      }
      if((sret == ((ssize_t)sizeof(exe_target)-1))
	 and (memcmp(splashy_name, exe_target,
		     sizeof(exe_target)-1) == 0)){
	splashy_pid = pid;
	break;
      }
    }
    closedir(proc_dir);
    proc_dir = NULL;
  }
  if(splashy_pid == 0){
    exitstatus = EX_UNAVAILABLE;
    goto failure;
  }
  
  /* Set up the signal handler */
  {
    struct sigaction old_action,
      new_action = { .sa_handler = termination_handler,
		     .sa_flags = 0 };
    sigemptyset(&new_action.sa_mask);
    ret = sigaddset(&new_action.sa_mask, SIGINT);
    if(ret == -1){
      error(0, errno, "sigaddset");
      exitstatus = EX_OSERR;
      goto failure;
    }
    ret = sigaddset(&new_action.sa_mask, SIGHUP);
    if(ret == -1){
      error(0, errno, "sigaddset");
      exitstatus = EX_OSERR;
      goto failure;
    }
    ret = sigaddset(&new_action.sa_mask, SIGTERM);
    if(ret == -1){
      error(0, errno, "sigaddset");
      exitstatus = EX_OSERR;
      goto failure;
    }
    ret = sigaction(SIGINT, NULL, &old_action);
    if(ret == -1){
      error(0, errno, "sigaction");
      exitstatus = EX_OSERR;
      goto failure;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGINT, &new_action, NULL);
      if(ret == -1){
	error(0, errno, "sigaction");
	exitstatus = EX_OSERR;
	goto failure;
      }
    }
    ret = sigaction(SIGHUP, NULL, &old_action);
    if(ret == -1){
      error(0, errno, "sigaction");
      exitstatus = EX_OSERR;
      goto failure;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGHUP, &new_action, NULL);
      if(ret == -1){
	error(0, errno, "sigaction");
	exitstatus = EX_OSERR;
	goto failure;
      }
    }
    ret = sigaction(SIGTERM, NULL, &old_action);
    if(ret == -1){
      error(0, errno, "sigaction");
      exitstatus = EX_OSERR;
      goto failure;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGTERM, &new_action, NULL);
      if(ret == -1){
	error(0, errno, "sigaction");
	exitstatus = EX_OSERR;
	goto failure;
      }
    }
  }
  
  if(interrupted_by_signal){
    goto failure;
  }
  
  /* Fork off the splashy command to prompt for password */
  splashy_command_pid = fork();
  if(splashy_command_pid != 0 and interrupted_by_signal){
    goto failure;
  }
  if(splashy_command_pid == -1){
    error(0, errno, "fork");
    exitstatus = EX_OSERR;
    goto failure;
  }
  /* Child */
  if(splashy_command_pid == 0){
    if(not interrupted_by_signal){
      const char splashy_command[] = "/sbin/splashy_update";
      execl(splashy_command, splashy_command, prompt, (char *)NULL);
      int e = errno;
      error(0, errno, "execl");
      switch(e){
      case EACCES:
      case ENOENT:
      case ENOEXEC:
      case EINVAL:
	_exit(EX_UNAVAILABLE);
      case ENAMETOOLONG:
      case E2BIG:
      case ENOMEM:
      case EFAULT:
      case EIO:
      case EMFILE:
      case ENFILE:
      case ETXTBSY:
      default:
	_exit(EX_OSERR);
      case ENOTDIR:
      case ELOOP:
      case EISDIR:
#ifdef ELIBBAD
      case ELIBBAD:		/* Linux only */
#endif
      case EPERM:
	_exit(EX_OSFILE);
      }
    }
    free(prompt);
    _exit(EXIT_FAILURE);
  }
  
  /* Parent */
  free(prompt);
  prompt = NULL;
  
  if(interrupted_by_signal){
    goto failure;
  }
  
  /* Wait for command to complete */
  {
    int status;
    do {
      ret = waitpid(splashy_command_pid, &status, 0);
    } while(ret == -1 and errno == EINTR
	    and not interrupted_by_signal);
    if(interrupted_by_signal){
      goto failure;
    }
    if(ret == -1){
      error(0, errno, "waitpid");
      if(errno == ECHILD){
	splashy_command_pid = 0;
      }
    } else {
      /* The child process has exited */
      splashy_command_pid = 0;
      if(WIFEXITED(status) and WEXITSTATUS(status) == 0){
	return EXIT_SUCCESS;
      }
    }
  }
  
 failure:
  
  free(prompt);
  
  if(proc_dir != NULL){
    TEMP_FAILURE_RETRY(closedir(proc_dir));
  }
  
  if(splashy_command_pid != 0){
    TEMP_FAILURE_RETRY(kill(splashy_command_pid, SIGTERM));
    
    TEMP_FAILURE_RETRY(kill(splashy_pid, SIGTERM));
    sleep(2);
    while(TEMP_FAILURE_RETRY(kill(splashy_pid, 0)) == 0){
      TEMP_FAILURE_RETRY(kill(splashy_pid, SIGKILL));
      sleep(1);
    }
    pid_t new_splashy_pid = (pid_t)TEMP_FAILURE_RETRY(fork());
    if(new_splashy_pid == 0){
      /* Child; will become new splashy process */
      
      /* Make the effective user ID (root) the only user ID instead of
	 the real user ID (_mandos) */
      ret = setuid(geteuid());
      if(ret == -1){
	error(0, errno, "setuid");
      }
      
      setsid();
      ret = chdir("/");
      if(ret == -1){
	error(0, errno, "chdir");
      }
/*       if(fork() != 0){ */
/* 	_exit(EXIT_SUCCESS); */
/*       } */
      ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace stdout */
      if(ret == -1){
	error(0, errno, "dup2");
	_exit(EX_OSERR);
      }
      
      execl("/sbin/splashy", "/sbin/splashy", "boot", (char *)NULL);
      {
	int e = errno;
	error(0, errno, "execl");
	switch(e){
	case EACCES:
	case ENOENT:
	case ENOEXEC:
	default:
	  _exit(EX_UNAVAILABLE);
	case ENAMETOOLONG:
	case E2BIG:
	case ENOMEM:
	  _exit(EX_OSERR);
	case ENOTDIR:
	case ELOOP:
	  _exit(EX_OSFILE);
	}
      }
    }
  }
  
  if(interrupted_by_signal){
    struct sigaction signal_action;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_handler = SIG_DFL;
    ret = (int)TEMP_FAILURE_RETRY(sigaction(signal_received,
					    &signal_action, NULL));
    if(ret == -1){
      error(0, errno, "sigaction");
    }
    do {
      ret = raise(signal_received);
    } while(ret != 0 and errno == EINTR);
    if(ret != 0){
      error(0, errno, "raise");
      abort();
    }
    TEMP_FAILURE_RETRY(pause());
  }
  
  return exitstatus;
}
