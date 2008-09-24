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
#include <stdbool.h>		/* bool, false, true */
#include <errno.h>		/* errno */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS() */
#include <fcntl.h>		/* open(), O_RDONLY */

sig_atomic_t interrupted_by_signal = 0;

static void termination_handler(__attribute__((unused))int signum){
  interrupted_by_signal = 1;
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
    const char *const prompt_start = "Enter passphrase to unlock the disk";
    
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
  {
    const char usplash_name[] = "/sbin/usplash";
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
      char exe_target[sizeof(usplash_name)];
      {
	char *exe_link;
	ret = asprintf(&exe_link, "/proc/%s/exe", proc_ent->d_name);
	if(ret == -1){
	  perror("asprintf");
	  free(prompt);
	  closedir(proc_dir);
	  return EXIT_FAILURE;
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
	  do{
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
  
  /* Write command to FIFO */
  if(not interrupted_by_signal){
    int fifo_fd = open("/dev/.initramfs/usplash_fifo", O_WRONLY);
    if(fifo_fd == -1){
      perror("open");
      free(prompt);
      return EXIT_FAILURE;
    }
    char *command;
    ret = asprintf(&command, "INPUTQUIET %s", prompt);
    if(ret == -1){
      perror("asprintf");
      free(prompt);
      return EXIT_FAILURE;
    }
    free(prompt);
    
    size_t command_len = (size_t)ret + 1;
    size_t written = 0;
    while(not interrupted_by_signal and written < command_len){
      ret = write(fifo_fd, command + written, command_len - written);
      if(ret == -1){
	if(interrupted_by_signal){
	  break;
	}
	perror("write");
	if(written == 0){
	  free(command);
	  return EXIT_FAILURE;
	}
	an_error_occured = true;
	break;
      }
      written += (size_t)ret;
    }
    ret = close(fifo_fd);
    if(ret == -1 and not interrupted_by_signal){
      an_error_occured = true;
    }
    free(command);
  }else{
    free(prompt);
  }
  
  {
    char *buf = NULL;
    size_t buf_len = 0;
    
    /* Read from FIFO */
    if(not interrupted_by_signal and not an_error_occured){
      int fifo_fd = open("/dev/.initramfs/usplash_outfifo", O_RDONLY);
      if(fifo_fd == -1 and not interrupted_by_signal){
	perror("open");
	return EXIT_FAILURE;
      }
      size_t buf_allocated = 0;
      const int blocksize = 1024;
      do{
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
	sret = read(fifo_fd, buf + buf_len, buf_allocated - buf_len);
	if(sret == -1){
	  perror("read");
	  an_error_occured = true;
	  break;
	}
	buf_len += (size_t)sret;
      }while(not interrupted_by_signal and sret != 0);
      close(fifo_fd);
    }
  
    /* Print password to stdout */
    if(not interrupted_by_signal and not an_error_occured){
      size_t written = 0;
      do{
	sret = write(STDOUT_FILENO, buf + written, buf_len - written);
	if(sret == -1 and not interrupted_by_signal){
	  perror("write");
	  an_error_occured = true;
	  break;
	}
	written += (size_t)sret;
      }while(written < buf_len);
      if(not interrupted_by_signal and not an_error_occured){
	return EXIT_SUCCESS;
      }
    }
  }
  
  kill(usplash_pid, SIGTERM);
  
  int cmdline_argc = 0;
  char **cmdline_argv = malloc(sizeof(char *));
  /* Create argv and argc for new usplash*/
  {
    ptrdiff_t position = 0;
    while((size_t)position < cmdline_len){
      char **tmp = realloc(cmdline_argv,
			   (sizeof(char *) * (size_t)(cmdline_argc + 2)));
      if(tmp == NULL){
	perror("realloc");
	free(cmdline_argv);
	return EXIT_FAILURE;
      }
      cmdline_argv = tmp;
      cmdline_argv[cmdline_argc] = cmdline + position;
      cmdline_argc++;
      position = (char *)rawmemchr(cmdline + position, '\0')
	- cmdline + 1;
    }
    cmdline_argv[cmdline_argc] = NULL;
  }
  pid_t new_usplash_pid = fork();
  if(new_usplash_pid == 0){
    /* Child; will become new usplash process */
    while(kill(usplash_pid, 0)){
      sleep(2);
      kill(usplash_pid, SIGKILL);
      sleep(1);
    }
    ret = dup2(STDERR_FILENO, STDOUT_FILENO); /* replace our stdout */
    if(ret == -1){
      perror("dup2");
      _exit(EXIT_FAILURE);
    }
    execv("/sbin/usplash", cmdline_argv);
  }
  
  return EXIT_FAILURE;
}
