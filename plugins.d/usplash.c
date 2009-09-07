/*  -*- coding: utf-8 -*- */
/*
 * Usplash - Read a password from usplash and output it
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

#define _GNU_SOURCE		/* asprintf() */
#include <signal.h>		/* sig_atomic_t, struct sigaction,
				   sigemptyset(), sigaddset(), SIGINT,
				   SIGHUP, SIGTERM, sigaction(),
				   SIG_IGN, kill(), SIGKILL */
#include <stdbool.h>		/* bool, false, true */
#include <fcntl.h>		/* open(), O_WRONLY, O_RDONLY */
#include <iso646.h>		/* and, or, not*/
#include <errno.h>		/* errno, EINTR */
#include <sys/types.h>		/* size_t, ssize_t, pid_t, DIR, struct
				   dirent */
#include <stddef.h>		/* NULL */
#include <string.h>		/* strlen(), memcmp() */
#include <stdio.h>		/* asprintf(), perror() */
#include <unistd.h>		/* close(), write(), readlink(),
				   read(), STDOUT_FILENO, sleep(),
				   fork(), setuid(), geteuid(),
				   setsid(), chdir(), dup2(),
				   STDERR_FILENO, execv() */
#include <stdlib.h>		/* free(), EXIT_FAILURE, realloc(),
				   EXIT_SUCCESS, malloc(), _exit() */
#include <stdlib.h>		/* getenv() */
#include <dirent.h>		/* opendir(), readdir(), closedir() */
#include <inttypes.h>		/* intmax_t, strtoimax() */
#include <sys/stat.h>		/* struct stat, lstat(), S_ISLNK */

sig_atomic_t interrupted_by_signal = 0;

static void termination_handler(__attribute__((unused))int signum){
  interrupted_by_signal = 1;
}

static bool usplash_write(const char *cmd, const char *arg){
  /* 
   * usplash_write("TIMEOUT", "15") will write "TIMEOUT 15\0"
   * usplash_write("PULSATE", NULL) will write "PULSATE\0"
   * SEE ALSO
   *         usplash_write(8)
   */
  int ret;
  int fifo_fd;
  do {
    fifo_fd = open("/dev/.initramfs/usplash_fifo", O_WRONLY);
    if(fifo_fd == -1 and (errno != EINTR or interrupted_by_signal)){
      return false;
    }
  } while(fifo_fd == -1);
  
  const char *cmd_line;
  size_t cmd_line_len;
  char *cmd_line_alloc = NULL;
  if(arg == NULL){
    cmd_line = cmd;
    cmd_line_len = strlen(cmd);
  } else {
    do {
      ret = asprintf(&cmd_line_alloc, "%s %s", cmd, arg);
      if(ret == -1 and (errno != EINTR or interrupted_by_signal)){
	int e = errno;
	close(fifo_fd);
	errno = e;
	return false;
      }
    } while(ret == -1);
    cmd_line = cmd_line_alloc;
    cmd_line_len = (size_t)ret + 1;
  }
  
  size_t written = 0;
  ssize_t sret = 0;
  while(not interrupted_by_signal and written < cmd_line_len){
    sret = write(fifo_fd, cmd_line + written,
		 cmd_line_len - written);
    if(sret == -1){
      if(errno != EINTR or interrupted_by_signal){
	int e = errno;
	close(fifo_fd);
	free(cmd_line_alloc);
	errno = e;
	return false;
      } else {
	continue;
      }
    }
    written += (size_t)sret;
  }
  free(cmd_line_alloc);
  do {
    ret = close(fifo_fd);
    if(ret == -1 and (errno != EINTR or interrupted_by_signal)){
      return false;
    }
  } while(ret == -1);
  if(interrupted_by_signal){
    return false;
  }
  return true;
}

int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  int ret = 0;
  ssize_t sret;
  bool an_error_occured = false;
  
  /* Create prompt string */
  char *prompt = NULL;
  {
    const char *const cryptsource = getenv("cryptsource");
    const char *const crypttarget = getenv("crypttarget");
    const char prompt_start[] = "Enter passphrase to unlock the disk";
    
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
      return EXIT_FAILURE;
    }
  }
  
  /* Find usplash process */
  pid_t usplash_pid = 0;
  char *cmdline = NULL;
  size_t cmdline_len = 0;
  const char usplash_name[] = "/sbin/usplash";
  {
    DIR *proc_dir = opendir("/proc");
    if(proc_dir == NULL){
      free(prompt);
      perror("opendir");
      return EXIT_FAILURE;
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
      char exe_target[sizeof(usplash_name)];
      {
	/* create file name string */
	char *exe_link;
	ret = asprintf(&exe_link, "/proc/%s/exe", proc_ent->d_name);
	if(ret == -1){
	  perror("asprintf");
	  free(prompt);
	  closedir(proc_dir);
	  return EXIT_FAILURE;
	}
	
	/* Check that it refers to a symlink owned by root:root */
	struct stat exe_stat;
	ret = lstat(exe_link, &exe_stat);
	if(ret == -1){
	  if(errno == ENOENT){
	    free(exe_link);
	    continue;
	  }
	  perror("lstat");
	  free(exe_link);
	  free(prompt);
	  closedir(proc_dir);
	  return EXIT_FAILURE;
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
	 and (memcmp(usplash_name, exe_target,
		     sizeof(exe_target)-1) == 0)){
	usplash_pid = pid;
	/* Read and save the command line of usplash in "cmdline" */
	{
	  /* Open /proc/<pid>/cmdline  */
	  int cl_fd;
	  {
	    char *cmdline_filename;
	    ret = asprintf(&cmdline_filename, "/proc/%s/cmdline",
			   proc_ent->d_name);
	    if(ret == -1){
	      perror("asprintf");
	      free(prompt);
	      closedir(proc_dir);
	      return EXIT_FAILURE;
	    }
	    cl_fd = open(cmdline_filename, O_RDONLY);
	    if(cl_fd == -1){
	      perror("open");
	      free(cmdline_filename);
	      free(prompt);
	      closedir(proc_dir);
	      return EXIT_FAILURE;
	    }
	    free(cmdline_filename);
	  }
	  size_t cmdline_allocated = 0;
	  char *tmp;
	  const size_t blocksize = 1024;
	  do {
	    if(cmdline_len + blocksize > cmdline_allocated){
	      tmp = realloc(cmdline, cmdline_allocated + blocksize);
	      if(tmp == NULL){
		perror("realloc");
		free(cmdline);
		free(prompt);
		closedir(proc_dir);
		return EXIT_FAILURE;
	      }
	      cmdline = tmp;
	      cmdline_allocated += blocksize;
	    }
	    sret = read(cl_fd, cmdline + cmdline_len,
			cmdline_allocated - cmdline_len);
	    if(sret == -1){
	      perror("read");
	      free(cmdline);
	      free(prompt);
	      closedir(proc_dir);
	      return EXIT_FAILURE;
	    }
	    cmdline_len += (size_t)sret;
	  } while(sret != 0);
	  close(cl_fd);
	}
	break;
      }
    }
    closedir(proc_dir);
  }
  if(usplash_pid == 0){
    free(prompt);
    return EXIT_FAILURE;
  }
  
  /* Set up the signal handler */
  {
    struct sigaction old_action,
      new_action = { .sa_handler = termination_handler,
		     .sa_flags = 0 };
    sigemptyset(&new_action.sa_mask);
    sigaddset(&new_action.sa_mask, SIGINT);
    sigaddset(&new_action.sa_mask, SIGHUP);
    sigaddset(&new_action.sa_mask, SIGTERM);
    ret = sigaction(SIGINT, NULL, &old_action);
    if(ret == -1){
      perror("sigaction");
      free(prompt);
      return EXIT_FAILURE;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGINT, &new_action, NULL);
      if(ret == -1){
	perror("sigaction");
	free(prompt);
	return EXIT_FAILURE;
      }
    }
    ret = sigaction(SIGHUP, NULL, &old_action);
    if(ret == -1){
      perror("sigaction");
      free(prompt);
      return EXIT_FAILURE;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGHUP, &new_action, NULL);
      if(ret == -1){
	perror("sigaction");
	free(prompt);
	return EXIT_FAILURE;
      }
    }
    ret = sigaction(SIGTERM, NULL, &old_action);
    if(ret == -1){
      perror("sigaction");
      free(prompt);
      return EXIT_FAILURE;
    }
    if(old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGTERM, &new_action, NULL);
      if(ret == -1){
	perror("sigaction");
	free(prompt);
	return EXIT_FAILURE;
      }
    }
  }
  
  /* Write command to FIFO */
  if(not interrupted_by_signal){
    if(not usplash_write("TIMEOUT", "0")
       and (errno != EINTR)){
      perror("usplash_write");
      an_error_occured = true;
    }
  }
  if(not interrupted_by_signal and not an_error_occured){
    if(not usplash_write("INPUTQUIET", prompt)
       and (errno != EINTR)){
      perror("usplash_write");
      an_error_occured = true;
    }
  }
  free(prompt);
  
  /* This is not really a loop; while() is used to be able to "break"
     out of it; those breaks are marked "Big" */
  while(not interrupted_by_signal and not an_error_occured){
    char *buf = NULL;
    size_t buf_len = 0;
    
    /* Open FIFO */
    int fifo_fd;
    do {
      fifo_fd = open("/dev/.initramfs/usplash_outfifo", O_RDONLY);
      if(fifo_fd == -1){
	if(errno != EINTR){
	  perror("open");
	  an_error_occured = true;
	  break;
	}
	if(interrupted_by_signal){
	  break;
	}
      }
    } while(fifo_fd == -1);
    if(interrupted_by_signal or an_error_occured){
      break;			/* Big */
    }
    
    /* Read from FIFO */
    size_t buf_allocated = 0;
    const size_t blocksize = 1024;
    do {
      if(buf_len + blocksize > buf_allocated){
	char *tmp = realloc(buf, buf_allocated + blocksize);
	if(tmp == NULL){
	  perror("realloc");
	  an_error_occured = true;
	  break;
	}
	buf = tmp;
	buf_allocated += blocksize;
      }
      do {
	sret = read(fifo_fd, buf + buf_len, buf_allocated - buf_len);
	if(sret == -1){
	  if(errno != EINTR){
	    perror("read");
	    an_error_occured = true;
	    break;
	  }
	  if(interrupted_by_signal){
	    break;
	  }
	}
      } while(sret == -1);
      if(interrupted_by_signal or an_error_occured){
	break;
      }
      
      buf_len += (size_t)sret;
    } while(sret != 0);
    close(fifo_fd);
    if(interrupted_by_signal or an_error_occured){
      break;			/* Big */
    }
    
    if(not usplash_write("TIMEOUT", "15")
       and (errno != EINTR)){
	perror("usplash_write");
	an_error_occured = true;
    }
    if(interrupted_by_signal or an_error_occured){
      break;			/* Big */
    }
    
    /* Print password to stdout */
    size_t written = 0;
    while(written < buf_len){
      do {
	sret = write(STDOUT_FILENO, buf + written, buf_len - written);
	if(sret == -1){
	  if(errno != EINTR){
	    perror("write");
	    an_error_occured = true;
	    break;
	  }
	  if(interrupted_by_signal){
	    break;
	  }
	}
      } while(sret == -1);
      if(interrupted_by_signal or an_error_occured){
	break;
      }
      written += (size_t)sret;
    }
    free(buf);
    if(not interrupted_by_signal and not an_error_occured){
      free(cmdline);
      return EXIT_SUCCESS;
    }
    break;			/* Big */
  }				/* end of non-loop while() */
  
  /* If we got here, an error or interrupt must have happened */
  
  /* Create argc and argv for new usplash*/
  int cmdline_argc = 0;
  char **cmdline_argv = malloc(sizeof(char *));
  {
    size_t position = 0;
    while(position < cmdline_len){
      char **tmp = realloc(cmdline_argv,
			   (sizeof(char *)
			    * (size_t)(cmdline_argc + 2)));
      if(tmp == NULL){
	perror("realloc");
	free(cmdline_argv);
	return EXIT_FAILURE;
      }
      cmdline_argv = tmp;
      cmdline_argv[cmdline_argc] = cmdline + position;
      cmdline_argc++;
      position += strlen(cmdline + position) + 1;
    }
    cmdline_argv[cmdline_argc] = NULL;
  }
  /* Kill old usplash */
  kill(usplash_pid, SIGTERM);
  sleep(2);
  while(kill(usplash_pid, 0) == 0){
    kill(usplash_pid, SIGKILL);
    sleep(1);
  }
  pid_t new_usplash_pid = fork();
  if(new_usplash_pid == 0){
    /* Child; will become new usplash process */
    
    /* Make the effective user ID (root) the only user ID instead of
       the real user ID (_mandos) */
    ret = setuid(geteuid());
    if(ret == -1){
      perror("setuid");
    }
    
    setsid();
    ret = chdir("/");
/*     if(fork() != 0){ */
/*       _exit(EXIT_SUCCESS); */
/*     } */
    ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace our stdout */
    if(ret == -1){
      perror("dup2");
      _exit(EXIT_FAILURE);
    }
    
    execv(usplash_name, cmdline_argv);
    if(not interrupted_by_signal){
      perror("execv");
    }
    free(cmdline);
    free(cmdline_argv);
    _exit(EXIT_FAILURE);
  }
  free(cmdline);
  free(cmdline_argv);
  sleep(2);
  if(not usplash_write("PULSATE", NULL)
     and (errno != EINTR)){
    perror("usplash_write");
  }
  
  return EXIT_FAILURE;
}
