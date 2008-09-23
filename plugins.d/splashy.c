#define _GNU_SOURCE		/* asprintf() */
#include <signal.h>		/* sig_atomic_t, struct sigaction,
				   sigemptyset(), sigaddset(),
				   sigaction, SIGINT, SIG_IGN, SIGHUP,
				   SIGTERM, kill(), SIGKILL */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* getenv() */
#include <stdio.h>		/* asprintf(), perror() */
#include <stdlib.h>		/* EXIT_FAILURE, EXIT_SUCCESS,
				   strtoul(), free() */
#include <sys/types.h>		/* pid_t, DIR, struct dirent,
				   ssize_t */
#include <dirent.h>		/* opendir(), readdir(), closedir() */
#include <unistd.h>		/* readlink(), fork(), execl(),
				   _exit */
#include <string.h>		/* memcmp() */
#include <iso646.h>		/* and */
#include <errno.h>		/* errno */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS() */

sig_atomic_t interrupted_by_signal = 0;

static void termination_handler(__attribute__((unused))int signum){
  interrupted_by_signal = 1;
}

int main(__attribute__((unused))int argc, char **argv){
  int ret = 0;
  
  /* Create prompt string */
  char *prompt = NULL;
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
      return EXIT_FAILURE;
    }
  }
  
  /* Find splashy process */
  pid_t splashy_pid = 0;
  {
    const char splashy_name[] = "/sbin/splashy";
    DIR *proc_dir = opendir("/proc");
    if(proc_dir == NULL){
      free(prompt);
      perror("opendir");
      return EXIT_FAILURE;
    }
    for(struct dirent *proc_ent = readdir(proc_dir);
	proc_ent != NULL;
	proc_ent = readdir(proc_dir)){
      pid_t pid = (pid_t) strtoul(proc_ent->d_name, NULL, 10);
      if(pid == 0){
	/* Not a process */
	continue;
      }
      /* Find the executable name by doing readlink() on the
	 /proc/<pid>/exe link */
      char *exe_link;
      ret = asprintf(&exe_link, "/proc/%s/exe", proc_ent->d_name);
      if(ret == -1){
	perror("asprintf");
	free(prompt);
	closedir(proc_dir);
	return EXIT_FAILURE;
      }
      char exe_target[sizeof(splashy_name)];
      ssize_t sret = readlink(exe_link, exe_target,
			      sizeof(exe_target));
      free(exe_link);
      if((sret == ((ssize_t)sizeof(exe_target)-1))
	 and (memcmp(splashy_name, exe_target,
		     sizeof(exe_target)-1) == 0)){
	splashy_pid = pid;
	break;
      }
    }
    closedir(proc_dir);
  }
  if(splashy_pid == 0){
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
    if (old_action.sa_handler != SIG_IGN){
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
    if (old_action.sa_handler != SIG_IGN){
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
    if (old_action.sa_handler != SIG_IGN){
      ret = sigaction(SIGTERM, &new_action, NULL);
      if(ret == -1){
	perror("sigaction");
	free(prompt);
	return EXIT_FAILURE;
      }
    }
  }
  
  /* Fork off the splashy command to prompt for password */
  pid_t splashy_command_pid = 0;
  if(not interrupted_by_signal){
    splashy_command_pid = fork();
    if(splashy_command_pid == -1){
      if(not interrupted_by_signal){
	perror("fork");
      }
      return EXIT_FAILURE;
    }
    /* Child */
    if(splashy_command_pid == 0){
      const char splashy_command[] = "/sbin/splashy_update";
      ret = execl(splashy_command, splashy_command, prompt,
		  (char *)NULL);
      if(not interrupted_by_signal and errno != ENOENT){
	/* Don't report "File not found", since splashy might not be
	   installed. */
	perror("execl");
      }
      free(prompt);
      return EXIT_FAILURE;
    }
  }
  
  /* Parent */
  free(prompt);
  
  /* Wait for command to complete */
  int status;
  while(not interrupted_by_signal){
    waitpid(splashy_command_pid, &status, 0);
    if(not interrupted_by_signal
       and WIFEXITED(status) and WEXITSTATUS(status)==0){
      return EXIT_SUCCESS;
    }
  }
  kill(splashy_pid, SIGTERM);
  if(interrupted_by_signal){
    kill(splashy_command_pid, SIGTERM);
  }
  
  pid_t new_splashy_pid = fork();
  if(new_splashy_pid == 0){
    /* Child; will become new splashy process */
    while(kill(splashy_pid, 0)){
      sleep(2);
      kill(splashy_pid, SIGKILL);
      sleep(1);
    }
    ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace our stdout */
    if(ret == -1){
      perror("dup2");
      _exit(EXIT_FAILURE);
    }
    execl("/sbin/splashy", "/sbin/splashy", "boot", (char *)NULL);
  }
  
  return EXIT_FAILURE;
}
