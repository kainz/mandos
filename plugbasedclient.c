#include <stdio.h>	/* popen, fileno */
#include <iso646.h>	/* and, or, not */
#include <sys/types.h>	/* DIR, opendir, stat, struct stat, waitpid,
			   WIFEXITED, WEXITSTATUS, wait */
#include <sys/wait.h>	/* wait */
#include <dirent.h>	/* DIR, opendir */
#include <sys/stat.h>	/* stat, struct stat */
#include <unistd.h>	/* stat, struct stat, chdir */
#include <stdlib.h>	/* EXIT_FAILURE */
#include <sys/select.h>	/* fd_set, select, FD_ZERO, FD_SET, FD_ISSET */
#include <string.h>	/* strlen, strcpy, strcat */
#include <stdbool.h>	/* true */
#include <sys/wait.h>	/* waitpid, WIFEXITED, WEXITSTATUS */
#include <errno.h>	/* errno */

struct process;

typedef struct process{
  pid_t pid;
  int fd;
  char *buffer;
  int buffer_size;
  int buffer_length;
  struct process *next;
} process;

#define BUFFER_SIZE 256

int main(int argc, char *argv[]){
  char plugindir[] = "plugins.d";
  size_t d_name_len, plugindir_len = sizeof(plugindir)-1;
  DIR *dir;
  struct dirent *dirst;
  struct stat st;
  fd_set rfds_orig;
  int ret, maxfd = 0;
  process *process_list = NULL;
  
  dir = opendir(plugindir);

  if(dir == NULL){
    fprintf(stderr, "Can not open directory\n");
    return EXIT_FAILURE;
  }
  
  FD_ZERO(&rfds_orig);
  
  while(true){
    dirst = readdir(dir);
    
    // All directory entries have been processed
    if(dirst == NULL){
      break;
    }
    
    d_name_len = strlen(dirst->d_name);
    
    // Ignore dotfiles and backup files
    if (dirst->d_name[0] == '.'
	or dirst->d_name[d_name_len - 1] == '~'){
      continue;
    }

    char *filename = malloc(d_name_len + plugindir_len + 2);
    strcpy(filename, plugindir);
    strcat(filename, "/");
    strcat(filename, dirst->d_name);    

    stat(filename, &st);

    if (S_ISREG(st.st_mode) and (access(filename, X_OK) == 0)){
      // Starting a new process to be watched
      process *new_process = malloc(sizeof(process));
      int pipefd[2];
      pipe(pipefd);
      new_process->pid = fork();
      if(new_process->pid == 0){
	/* this is the child process */
	closedir(dir);
	close(pipefd[0]);	/* close unused read end of pipe */
	dup2(pipefd[1], STDOUT_FILENO); /* replace our stdout */
	/* create a new modified argument list */
	char **new_argv = malloc(sizeof(char *) * (argc + 1));
	new_argv[0] = filename;
	for(int i = 1; i < argc; i++){
	  new_argv[i] = argv[i];
	}
	new_argv[argc] = NULL;
	if(execv(filename, new_argv) < 0){
	  perror(argv[0]);
	  close(pipefd[1]);
	  exit(EXIT_FAILURE);
	}
	/* no return */
      }
      close(pipefd[1]);		/* close unused write end of pipe */
      new_process->fd = pipefd[0];
      new_process->buffer = malloc(BUFFER_SIZE);
      if (new_process->buffer == NULL){
	perror(argv[0]);
	goto end;
      }
      new_process->buffer_size = BUFFER_SIZE;
      new_process->buffer_length = 0;
      FD_SET(new_process->fd, &rfds_orig);
      
      if (maxfd < new_process->fd){
	maxfd = new_process->fd;
      }
      
      //List handling
      new_process->next = process_list;
      process_list = new_process;
    }
  }
  
  closedir(dir);
  
  if (process_list != NULL){
    while(true){
      fd_set rfds = rfds_orig;
      int select_ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
      if (select_ret == -1){
	perror(argv[0]);
	goto end;
      }else{	
	for(process *process_itr = process_list; process_itr != NULL;
	    process_itr = process_itr->next){
	  if(FD_ISSET(process_itr->fd, &rfds)){
	    if(process_itr->buffer_length + BUFFER_SIZE
	       > process_itr->buffer_size){
		process_itr->buffer = realloc(process_itr->buffer,
					      process_itr->buffer_size
					      + BUFFER_SIZE);
		if (process_itr->buffer == NULL){
		  perror(argv[0]);
		  goto end;
		}
		process_itr->buffer_size += BUFFER_SIZE;
	    }
	    ret = read(process_itr->fd, process_itr->buffer
		       + process_itr->buffer_length, BUFFER_SIZE);
	    process_itr->buffer_length+=ret;
	    if(ret == 0){
	      /* got EOF */
	      /* wait for process exit */
	      int status;
	      waitpid(process_itr->pid, &status, 0);
	      if(WIFEXITED(status) and WEXITSTATUS(status) == 0){
		write(STDOUT_FILENO, process_itr->buffer,
		      process_itr->buffer_length);
		goto end;
	      } else {
		FD_CLR(process_itr->fd, &rfds_orig);
	      }
	    }
	  }
	}
      }
    }
  }
  
 end:
  for(process *process_itr = process_list; process_itr != NULL;
      process_itr = process_itr->next){
    close(process_itr->fd);
    kill(process_itr->pid, SIGTERM);
    free(process_itr->buffer);
  }
  
  while(true){
    int status;
    ret = wait(&status);
    if (ret == -1){
      if(errno != ECHILD){
	perror("wait");
      }
      break;
    }
  }  
  return EXIT_SUCCESS;
}
