/*  -*- coding: utf-8 -*- */
/*
 * Plymouth - Read a password from Plymouth and output it
 * 
 * Copyright © 2010-2020 Teddy Hogeborn
 * Copyright © 2010-2020 Björn Påhlsson
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

#define _GNU_SOURCE		/* program_invocation_short_name,
				   vasprintf(), asprintf(),
				   TEMP_FAILURE_RETRY() */
#include <sys/types.h>		/* sig_atomic_t, pid_t, setuid(),
				   geteuid(), setsid() */
#include <argp.h>		/* argp_program_version,
				   argp_program_bug_address,
				   struct argp_option,
				   struct argp_state,
				   ARGP_ERR_UNKNOWN, struct argp,
				   argp_parse(), ARGP_IN_ORDER */
#include <stddef.h>		/* NULL, size_t */
#include <stdbool.h>		/* bool, false, true */
#include <stdio.h>		/* FILE, fprintf(), vfprintf(),
				   vasprintf(), stderr, asprintf(),
				   fopen(), fscanf(), fclose(),
				   sscanf() */
#include <stdarg.h>		/* va_list, va_start(), vfprintf() */
#include <errno.h>		/* program_invocation_short_name,
				   errno, ENOMEM, EINTR, ENOENT,
				   error_t, EINVAL */
#include <string.h>		/* strerror(), strdup(), memcmp() */
#include <error.h>		/* error() */
#include <stdlib.h>		/* free(), getenv(), malloc(),
				   reallocarray(), realloc(),
				   EXIT_FAILURE, EXIT_SUCCESS */
#include <unistd.h>		/* TEMP_FAILURE_RETRY(), setuid(),
				   geteuid(), setsid(), chdir(),
				   dup2(), STDERR_FILENO,
				   STDOUT_FILENO, fork(), _exit(),
				   execv(), ssize_t, readlink(),
				   close(), read(), access(), X_OK */
#include <signal.h>		/* kill(), SIGTERM, struct sigaction,
				   sigemptyset(), SIGINT, SIGHUP,
				   sigaddset(), SIG_IGN */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS(), WIFSIGNALED(),
				   WTERMSIG() */
#include <iso646.h>		/* not, and, or */
#include <sysexits.h>		/* EX_OSERR, EX_USAGE,
				   EX_UNAVAILABLE */
#include <stdint.h>		/* SIZE_MAX */
#include <dirent.h>		/* struct dirent, scandir(),
				   alphasort() */
#include <inttypes.h>		/* uintmax_t, strtoumax(), SCNuMAX,
				   PRIuMAX */
#include <sys/stat.h>		/* struct stat, lstat(), S_ISLNK() */
#include <fcntl.h>		/* open(), O_RDONLY */
#include <argz.h>		/* argz_count(), argz_extract() */

sig_atomic_t interrupted_by_signal = 0;
const char *argp_program_version = "plymouth " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";

/* Used by Ubuntu 11.04 (Natty Narwahl) */
const char plymouth_old_old_pid[] = "/dev/.initramfs/plymouth.pid";
/* Used by Ubuntu 11.10 (Oneiric Ocelot) */
const char plymouth_old_pid[] = "/run/initramfs/plymouth.pid";
/* Used by Debian 9 (stretch) */
const char plymouth_pid[] = "/run/plymouth/pid";

const char plymouth_path[] = "/bin/plymouth";
const char plymouthd_path[] = "/sbin/plymouthd";
const char *plymouthd_default_argv[] = {"/sbin/plymouthd",
					"--mode=boot",
					"--attach-to-session",
					NULL };
bool debug = false;

static void termination_handler(__attribute__((unused))int signum){
  if(interrupted_by_signal){
    return;
  }
  interrupted_by_signal = 1;
}

__attribute__((format (gnu_printf, 2, 3), nonnull))
int fprintf_plus(FILE *stream, const char *format, ...){
  va_list ap;
  va_start (ap, format);
  fprintf(stream, "Mandos plugin %s: ", program_invocation_short_name);
  return vfprintf(stream, format, ap);
}

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
    fprintf(stderr, ": ");
    fprintf(stderr, "%s\n", strerror(errnum));
    error(status, errno, "vasprintf while printing error");
    return;
  }
  fprintf(stderr, "Mandos plugin ");
  error(status, errnum, "%s", text);
  free(text);
}

/* Create prompt string */
char *makeprompt(void){
  int ret = 0;
  char *prompt;
  const char *const cryptsource = getenv("cryptsource");
  const char *const crypttarget = getenv("crypttarget");
  const char prompt_start[] = "Unlocking the disk";
  const char prompt_end[] = "Enter passphrase";
  
  if(cryptsource == NULL){
    if(crypttarget == NULL){
      ret = asprintf(&prompt, "%s\n%s", prompt_start, prompt_end);
    } else {
      ret = asprintf(&prompt, "%s (%s)\n%s", prompt_start,
		     crypttarget, prompt_end);
    }
  } else {
    if(crypttarget == NULL){
      ret = asprintf(&prompt, "%s %s\n%s", prompt_start, cryptsource,
		     prompt_end);
    } else {
      ret = asprintf(&prompt, "%s %s (%s)\n%s", prompt_start,
		     cryptsource, crypttarget, prompt_end);
    }
  }
  if(ret == -1){
    return NULL;
  }
  return prompt;
}

void kill_and_wait(pid_t pid){
  TEMP_FAILURE_RETRY(kill(pid, SIGTERM));
  TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
}

bool become_a_daemon(void){
  int ret = setuid(geteuid());
  if(ret == -1){
    error_plus(0, errno, "setuid");
  }
    
  setsid();
  ret = chdir("/");
  if(ret == -1){
    error_plus(0, errno, "chdir");
    return false;
  }
  ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace our stdout */
  if(ret == -1){
    error_plus(0, errno, "dup2");
    return false;
  }
  return true;
}

__attribute__((nonnull (2, 3)))
bool exec_and_wait(pid_t *pid_return, const char *path,
		   const char * const * const argv, bool interruptable,
		   bool daemonize){
  int status;
  int ret;
  pid_t pid;
  if(debug){
    for(const char * const *arg = argv; *arg != NULL; arg++){
      fprintf_plus(stderr, "exec_and_wait arg: %s\n", *arg);
    }
    fprintf_plus(stderr, "exec_and_wait end of args\n");
  }

  pid = fork();
  if(pid == -1){
    error_plus(0, errno, "fork");
    return false;
  }
  if(pid == 0){
    /* Child */
    if(daemonize){
      if(not become_a_daemon()){
	_exit(EX_OSERR);
      }
    }
    
    char **new_argv = malloc(sizeof(const char *));
    if(new_argv == NULL){
      error_plus(0, errno, "malloc");
      _exit(EX_OSERR);
    }
    char **tmp;
    int i = 0;
    for (; argv[i] != NULL; i++){
#if defined(__GLIBC_PREREQ) and __GLIBC_PREREQ(2, 26)
      tmp = reallocarray(new_argv, ((size_t)i + 2),
			 sizeof(const char *));
#else
      if(((size_t)i + 2) > (SIZE_MAX / sizeof(const char *))){
	/* overflow */
	tmp = NULL;
	errno = ENOMEM;
      } else {
	tmp = realloc(new_argv, ((size_t)i + 2) * sizeof(const char *));
      }
#endif
      if(tmp == NULL){
	error_plus(0, errno, "reallocarray");
	free(new_argv);
	_exit(EX_OSERR);
      }
      new_argv = tmp;
      new_argv[i] = strdup(argv[i]);
    }
    new_argv[i] = NULL;
    
    execv(path, (char *const *)new_argv);
    error_plus(0, errno, "execv");
    _exit(EXIT_FAILURE);
  }
  if(pid_return != NULL){
    *pid_return = pid;
  }
  do {
    ret = waitpid(pid, &status, 0);
  } while(ret == -1 and errno == EINTR
	  and ((not interrupted_by_signal)
	       or (not interruptable)));
  if(interrupted_by_signal and interruptable){
    if(debug){
      fprintf_plus(stderr, "Interrupted by signal\n");
    }
    return false;
  }
  if(ret == -1){
    error_plus(0, errno, "waitpid");
    return false;
  }
  if(debug){
    if(WIFEXITED(status)){
      fprintf_plus(stderr, "exec_and_wait exited: %d\n",
		   WEXITSTATUS(status));
    } else if(WIFSIGNALED(status)) {
      fprintf_plus(stderr, "exec_and_wait signaled: %d\n",
		   WTERMSIG(status));
    }
  }
  if(WIFEXITED(status) and (WEXITSTATUS(status) == 0)){
    return true;
  }
  return false;
}

__attribute__((nonnull))
int is_plymouth(const struct dirent *proc_entry){
  int ret;
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
  char exe_target[sizeof(plymouthd_path)];
  char *exe_link;
  ret = asprintf(&exe_link, "/proc/%s/exe", proc_entry->d_name);
  if(ret == -1){
    error_plus(0, errno, "asprintf");
    return 0;
  }
  
  struct stat exe_stat;
  ret = lstat(exe_link, &exe_stat);
  if(ret == -1){
    free(exe_link);
    if(errno != ENOENT){
      error_plus(0, errno, "lstat");
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

pid_t get_pid(void){
  int ret;
  uintmax_t proc_id = 0;
  FILE *pidfile = fopen(plymouth_pid, "r");
  /* Try the new pid file location */
  if(pidfile != NULL){
    ret = fscanf(pidfile, "%" SCNuMAX, &proc_id);
    if(ret != 1){
      proc_id = 0;
    }
    fclose(pidfile);
  }
  /* Try the old pid file location */
  if(proc_id == 0){
    pidfile = fopen(plymouth_old_pid, "r");
    if(pidfile != NULL){
      ret = fscanf(pidfile, "%" SCNuMAX, &proc_id);
      if(ret != 1){
	proc_id = 0;
      }
      fclose(pidfile);
    }
  }
  /* Try the old old pid file location */
  if(proc_id == 0){
    pidfile = fopen(plymouth_old_old_pid, "r");
    if(pidfile != NULL){
      ret = fscanf(pidfile, "%" SCNuMAX, &proc_id);
      if(ret != 1){
	proc_id = 0;
      }
      fclose(pidfile);
    }
  }
  /* Look for a plymouth process */
  if(proc_id == 0){
    struct dirent **direntries = NULL;
    ret = scandir("/proc", &direntries, is_plymouth, alphasort);
    if(ret == -1){
      error_plus(0, errno, "scandir");
    }
    if(ret > 0){
      for(int i = ret-1; i >= 0; i--){
	if(proc_id == 0){
	  ret = sscanf(direntries[i]->d_name, "%" SCNuMAX, &proc_id);
	  if(ret < 0){
	    error_plus(0, errno, "sscanf");
	  }
	}
	free(direntries[i]);
      }
    }
    /* scandir might preallocate for this variable (man page unclear).
       even if ret == 0, therefore we need to free it. */
    free(direntries);
  }
  pid_t pid;
  pid = (pid_t)proc_id;
  if((uintmax_t)pid == proc_id){
    return pid;
  }
  
  return 0;
}

char **getargv(pid_t pid){
  int cl_fd;
  char *cmdline_filename;
  ssize_t sret;
  int ret;
  
  ret = asprintf(&cmdline_filename, "/proc/%" PRIuMAX "/cmdline",
		 (uintmax_t)pid);
  if(ret == -1){
    error_plus(0, errno, "asprintf");
    return NULL;
  }
  
  /* Open /proc/<pid>/cmdline  */
  cl_fd = open(cmdline_filename, O_RDONLY);
  free(cmdline_filename);
  if(cl_fd == -1){
    error_plus(0, errno, "open");
    return NULL;
  }
  
  size_t cmdline_allocated = 0;
  size_t cmdline_len = 0;
  char *cmdline = NULL;
  char *tmp;
  const size_t blocksize = 1024;
  do {
    /* Allocate more space? */
    if(cmdline_len + blocksize > cmdline_allocated){
      tmp = realloc(cmdline, cmdline_allocated + blocksize);
      if(tmp == NULL){
	error_plus(0, errno, "realloc");
	free(cmdline);
	close(cl_fd);
	return NULL;
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
      return NULL;
    }
    cmdline_len += (size_t)sret;
  } while(sret != 0);
  ret = close(cl_fd);
  if(ret == -1){
    error_plus(0, errno, "close");
    free(cmdline);
    return NULL;
  }
  
  /* we got cmdline and cmdline_len, ignore rest... */
  char **argv = malloc((argz_count(cmdline, cmdline_len) + 1)
		       * sizeof(char *)); /* Get number of args */
  if(argv == NULL){
    error_plus(0, errno, "argv = malloc()");
    free(cmdline);
    return NULL;
  }
  argz_extract(cmdline, cmdline_len, argv); /* Create argv */
  return argv;
}

int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  char *prompt = NULL;
  char *prompt_arg;
  pid_t plymouth_command_pid;
  int ret;
  bool bret;

  {
    struct argp_option options[] = {
      { .name = "prompt", .key = 128, .arg = "PROMPT",
	.doc = "The prompt to show" },
      { .name = "debug", .key = 129,
	.doc = "Debug mode" },
      { .name = NULL }
    };
    
    __attribute__((nonnull(3)))
    error_t parse_opt (int key, char *arg, __attribute__((unused))
		       struct argp_state *state){
      errno = 0;
      switch (key){
      case 128:			/* --prompt */
	prompt = arg;
	if(debug){
	  fprintf_plus(stderr, "Custom prompt \"%s\"\n", prompt);
	}
	break;
      case 129:			/* --debug */
	debug = true;
	break;
      default:
	return ARGP_ERR_UNKNOWN;
      }
      return errno;
    }
    
    struct argp argp = { .options = options, .parser = parse_opt,
			 .args_doc = "",
			 .doc = "Mandos plymouth -- Read and"
			 " output a password" };
    ret = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);
    switch(ret){
    case 0:
      break;
    case ENOMEM:
    default:
      errno = ret;
      error_plus(0, errno, "argp_parse");
      return EX_OSERR;
    case EINVAL:
      error_plus(0, errno, "argp_parse");
      return EX_USAGE;
    }
  }
  
  /* test -x /bin/plymouth */
  ret = access(plymouth_path, X_OK);
  if(ret == -1){
    /* Plymouth is probably not installed.  Don't print an error
       message, just exit. */
    if(debug){
      fprintf_plus(stderr, "Plymouth (%s) not found\n",
		   plymouth_path);
    }
    exit(EX_UNAVAILABLE);
  }
  
  { /* Add signal handlers */
    struct sigaction old_action,
      new_action = { .sa_handler = termination_handler,
		     .sa_flags = 0 };
    sigemptyset(&new_action.sa_mask);
    for(int *sig = (int[]){ SIGINT, SIGHUP, SIGTERM, 0 };
	*sig != 0; sig++){
      ret = sigaddset(&new_action.sa_mask, *sig);
      if(ret == -1){
	error_plus(EX_OSERR, errno, "sigaddset");
      }
      ret = sigaction(*sig, NULL, &old_action);
      if(ret == -1){
	error_plus(EX_OSERR, errno, "sigaction");
      }
      if(old_action.sa_handler != SIG_IGN){
	ret = sigaction(*sig, &new_action, NULL);
	if(ret == -1){
	  error_plus(EX_OSERR, errno, "sigaction");
	}
      }
    }
  }
  
  /* plymouth --ping */
  bret = exec_and_wait(&plymouth_command_pid, plymouth_path,
		       (const char *[])
		       { plymouth_path, "--ping", NULL },
		       true, false);
  if(not bret){
    if(interrupted_by_signal){
      kill_and_wait(plymouth_command_pid);
      exit(EXIT_FAILURE);
    }
    /* Plymouth is probably not running.  Don't print an error
       message, just exit. */
    if(debug){
      fprintf_plus(stderr, "Plymouth not running\n");
    }
    exit(EX_UNAVAILABLE);
  }
  
  if(prompt != NULL){
    ret = asprintf(&prompt_arg, "--prompt=%s", prompt);
  } else {
    char *made_prompt = makeprompt();
    ret = asprintf(&prompt_arg, "--prompt=%s", made_prompt);
    free(made_prompt);
  }
  if(ret == -1){
    error_plus(EX_OSERR, errno, "asprintf");
  }
  
  /* plymouth ask-for-password --prompt="$prompt" */
  if(debug){
    fprintf_plus(stderr, "Prompting for password via Plymouth\n");
  }
  bret = exec_and_wait(&plymouth_command_pid,
		       plymouth_path, (const char *[])
		       { plymouth_path, "ask-for-password",
			   prompt_arg, NULL },
		       true, false);
  free(prompt_arg);
  if(bret){
    exit(EXIT_SUCCESS);
  }
  if(not interrupted_by_signal){
    /* exec_and_wait failed for some other reason */
    exit(EXIT_FAILURE);
  }
  kill_and_wait(plymouth_command_pid);
  
  char **plymouthd_argv = NULL;
  pid_t pid = get_pid();
  if(pid == 0){
    error_plus(0, 0, "plymouthd pid not found");
  } else {
    plymouthd_argv = getargv(pid);
  }
  
  bret = exec_and_wait(NULL, plymouth_path, (const char *[])
		       { plymouth_path, "quit", NULL },
		       false, false);
  if(not bret){
    if(plymouthd_argv != NULL){
      free(*plymouthd_argv);
      free(plymouthd_argv);
    }
    exit(EXIT_FAILURE);
  }
  bret = exec_and_wait(NULL, plymouthd_path,
		       (plymouthd_argv != NULL)
		       ? (const char * const *)plymouthd_argv
		       : plymouthd_default_argv,
		       false, true);
  if(plymouthd_argv != NULL){
    free(*plymouthd_argv);
    free(plymouthd_argv);
  }
  if(not bret){
    exit(EXIT_FAILURE);
  }
  exec_and_wait(NULL, plymouth_path, (const char *[])
		{ plymouth_path, "show-splash", NULL },
		false, false);
  exit(EXIT_FAILURE);
}
