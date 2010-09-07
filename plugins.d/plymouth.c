#define _GNU_SOURCE		/* asprintf(), TEMP_FAILURE_RETRY() */
#include <signal.h>		/* sig_atomic_t, struct sigaction,
				   sigemptyset(), sigaddset(), SIGINT,
				   SIGHUP, SIGTERM, sigaction(),
				   kill(), SIG_IGN */
#include <stdbool.h>		/* bool, false, true */
#include <fcntl.h>		/* open(), O_RDONLY */
#include <iso646.h>		/* and, or, not*/
#include <sys/types.h>		/* size_t, ssize_t, pid_t, struct dirent,
				   waitpid() */
#include <sys/wait.h>		/* waitpid() */
#include <stddef.h>		/* NULL */
#include <string.h>		/* strchr(), memcmp() */
#include <stdio.h>		/* asprintf(), perror(), fopen(), fscanf() */
#include <unistd.h>		/* close(), readlink(), read(), fork()
				   setsid(), chdir(), dup2()
				   STDERR_FILENO, execv(), access() */
#include <stdlib.h>		/* free(), EXIT_FAILURE, realloc(),
				   EXIT_SUCCESS, malloc(), _exit(),
				   getenv() */
#include <dirent.h>		/* scandir(), alphasort() */
#include <inttypes.h>		/* intmax_t, strtoumax(), SCNuMAX */
#include <sys/stat.h>		/* struct stat, lstat() */
#include <sysexits.h>		/* EX_OSERR */
#include <error.h>		/* error() */
#include <errno.h>		/* TEMP_FAILURE_RETRY */
#include <stdarg.h>

sig_atomic_t interrupted_by_signal = 0;
const char plymouth_pid[] = "/dev/.initramfs/plymouth.pid";
const char plymouth_path[] = "/bin/plymouth";
const char plymouthd_path[] = "/sbin/plymouthd";
const char *plymouthd_default_argv[] = {"/sbin/plymouthd", "--mode=boot",
					"--attach-to-session",
					"--pid-file=/dev/.initramfs/plymouth.pid",
					NULL };

static void termination_handler(__attribute__((unused))int signum){
  if(interrupted_by_signal){
    return;
  }
  interrupted_by_signal = 1;
}

/* Create prompt string */
char *makeprompt(void){
  int ret = 0;
  char *prompt;
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
    error(0, errno, "setuid");
  }
    
  setsid();
  ret = chdir("/");
  if(ret == -1){
    error(0, errno, "chdir");
    return false;
  }
  ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace our stdout */
  if(ret == -1){
    error(0, errno, "dup2");
    return false;
  }
  return true;
}

bool exec_and_wait(pid_t *pid_return, const char *path,
		   const char **argv, bool interruptable,
		   bool daemonize){
  int status;
  int ret;
  pid_t pid;
  pid = fork();
  if(pid == -1){
    error(0, errno, "fork");
    return false;
  }
  if(pid == 0){
    /* Child */
    if(daemonize){
      if(not become_a_daemon()){
	_exit(EX_OSERR);
      }
    }

    char **new_argv = NULL;
    char *tmp;
    int i = 0;
    for (; argv[i]!=(char *)NULL; i++){
      tmp = realloc(new_argv, sizeof(const char *) * ((size_t)i + 1));
      if (tmp == NULL){
	error(0, errno, "realloc");
	free(new_argv);
	_exit(EXIT_FAILURE);
      }
      new_argv = (char **)tmp;
      new_argv[i] = strdup(argv[i]);
    }
    new_argv[i] = (char *) NULL;
    
    execv(path, (char *const *)new_argv);
    error(0, errno, "execv");
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
    return false;
  }
  if(ret == -1){
    error(0, errno, "waitpid");
    return false;
  }
  if(WIFEXITED(status) and WEXITSTATUS(status) == 0){
    return true;
  }
  return false;
}

int is_plymouth(const struct dirent *proc_entry){
  int ret;
  {
    uintmax_t maxvalue;
    char *tmp;
    errno = 0;
    maxvalue = strtoumax(proc_entry->d_name, &tmp, 10);

    if(errno != 0 or *tmp != '\0' or maxvalue != (uintmax_t)((pid_t)maxvalue)){
      return 0;
    }
  }
  char exe_target[sizeof(plymouth_path)];
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
  if((sret != (ssize_t)sizeof(plymouth_path)-1) or
      (memcmp(plymouth_path, exe_target,
	      sizeof(plymouth_path)-1) != 0)){
    return 0;
  }
  return 1;
}

pid_t get_pid(void){
  int ret;
  FILE *pidfile = fopen(plymouth_pid, "r");
  uintmax_t maxvalue = 0;
  if(pidfile != NULL){
    ret = fscanf(pidfile, "%" SCNuMAX, &maxvalue);
    if(ret != 1){
      maxvalue = 0;
    }
    fclose(pidfile);
  }
  if(maxvalue == 0){
    struct dirent **direntries;
    ret = scandir("/proc", &direntries, is_plymouth, alphasort);
    sscanf(direntries[0]->d_name, "%" SCNuMAX, &maxvalue);
  }
  pid_t pid;
  pid = (pid_t)maxvalue;
  if((uintmax_t)pid == maxvalue){
    return pid;
  }
  
  return 0;
}

const char **getargv(pid_t pid){
  int cl_fd;
  char *cmdline_filename;
  ssize_t sret;
  int ret;
  
  ret = asprintf(&cmdline_filename, "/proc/%" PRIuMAX "/cmdline",
		 (uintmax_t)pid);
  if(ret == -1){
    error(0, errno, "asprintf");
    return NULL;
  }
  
  /* Open /proc/<pid>/cmdline  */
  cl_fd = open(cmdline_filename, O_RDONLY);
  free(cmdline_filename);
  if(cl_fd == -1){
    error(0, errno, "open");
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
	error(0, errno, "realloc");
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
      error(0, errno, "read");
      free(cmdline);
      close(cl_fd);
      return NULL;
    }
    cmdline_len += (size_t)sret;
  } while(sret != 0);
  ret = close(cl_fd);
  if(ret == -1){
    error(0, errno, "close");
    free(cmdline);
    return NULL;
  }
  
  /* we got cmdline and cmdline_len, ignore rest... */
  const char **argv = NULL;
  size_t argv_size = 0;
  for(char *arg = cmdline; arg-cmdline < (ssize_t)cmdline_len;
      arg = strchr(arg, '\0')+1){
    tmp = realloc(argv, ((++argv_size)+1)*sizeof(char *));
    if(tmp == NULL){
      error(0, errno, "realloc");
      free(argv);
      return NULL;
    }
    argv = (const char **)tmp;
    argv[argv_size-1] = arg;
  }
  argv[argv_size] = NULL;
  return argv;
}

int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  char *prompt;
  char *prompt_arg;
  pid_t plymouth_command_pid;
  int ret;
  bool bret;

  /* test -x /bin/plymouth */
  ret = access(plymouth_path, X_OK);
  if(ret == -1){
    exit(EXIT_FAILURE);
  }

  { /* Add signal handlers */
    struct sigaction old_action,
      new_action = { .sa_handler = termination_handler,
		     .sa_flags = 0 };
    sigemptyset(&new_action.sa_mask);
    for(int *sig = (int[]){ SIGINT, SIGHUP, SIGTERM, 0 }; *sig != 0; sig++){
      ret = sigaddset(&new_action.sa_mask, *sig);
      if(ret == -1){
	error(0, errno, "sigaddset");
	exit(EX_OSERR);
      }
      ret = sigaction(*sig, NULL, &old_action);
      if(ret == -1){
	error(0, errno, "sigaction");
	exit(EX_OSERR);
      }
      if(old_action.sa_handler != SIG_IGN){
	ret = sigaction(*sig, &new_action, NULL);
	if(ret == -1){
	  error(0, errno, "sigaction");
	  exit(EX_OSERR);
	}
      }
    }
  }
    
  /* plymouth --ping */
  bret = exec_and_wait(&plymouth_command_pid, plymouth_path,
		       (const char *[]){ (const char *)plymouth_path, (const char *)"--ping", (const char *)NULL},
		       true, false);
  if(not bret){
    if(interrupted_by_signal){
      kill_and_wait(plymouth_command_pid);
    }
    exit(EXIT_FAILURE);
  }
  
  prompt = makeprompt();
  ret = asprintf(&prompt_arg, "--prompt=%s", prompt);
  free(prompt);
  if(ret == -1){
    error(0, errno, "asprintf");
    exit(EXIT_FAILURE);
  }
  
  /* plymouth ask-for-password --prompt="$prompt" */
  bret = exec_and_wait(&plymouth_command_pid, plymouth_path,
		       (const char *[]){plymouth_path, "ask-for-password", prompt_arg, NULL},
		       true, false);
  free(prompt_arg);
  if(not bret){
    if(interrupted_by_signal){
      kill_and_wait(plymouth_command_pid);
    } else {
      exit(EXIT_FAILURE);
    }
  }
  
  if(bret){
    exit(EXIT_SUCCESS);
  }
  
  const char **plymouthd_argv = NULL;
  pid_t pid = get_pid();
  if(pid == 0){
    error(0, 0, "plymouthd pid not found");
  } else {
    plymouthd_argv = getargv(pid);
  }
  if(plymouthd_argv == NULL){
    plymouthd_argv = plymouthd_default_argv;
  }
  
  bret = exec_and_wait(NULL, plymouth_path,
  		       (const char *[]){plymouth_path, "quit", NULL}, false, false);
  if(not bret){
    exit(EXIT_FAILURE);
  }
  bret = exec_and_wait(NULL, plymouthd_path, plymouthd_argv, false, true);
  if(not bret){
    exit(EXIT_FAILURE);
  }
  exec_and_wait(NULL, plymouth_path,
  		(const char *[]){ plymouth_path, "show-splash", NULL }, false, false);
  exit(EXIT_FAILURE);
}
