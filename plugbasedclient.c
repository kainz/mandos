/*  -*- coding: utf-8 -*- */
/*
 * Mandos plugin runner - Run Mandos plugins
 *
 * Copyright © 2007-2008 Teddy Hogeborn & Björn Påhlsson
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

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY() */

#include <stdio.h>		/* popen(), fileno(), fprintf(),
				   stderr, STDOUT_FILENO */
#include <iso646.h>		/* and, or, not */
#include <sys/types.h>	        /* DIR, opendir(), stat(),
				   struct stat, waitpid(),
				   WIFEXITED(), WEXITSTATUS(),
				   wait() */
#include <sys/wait.h>		/* wait() */
#include <dirent.h>		/* DIR, struct dirent, opendir(),
				   readdir(), closedir() */
#include <sys/stat.h>		/* struct stat, stat(), S_ISREG() */
#include <unistd.h>		/* struct stat, stat(), S_ISREG(),
				   fcntl() */
#include <fcntl.h>		/* fcntl() */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* EXIT_FAILURE */
#include <sys/select.h>		/* fd_set, select(), FD_ZERO(),
				   FD_SET(), FD_ISSET() */
#include <string.h>		/* strlen(), strcpy(), strcat() */
#include <stdbool.h>		/* true */
#include <sys/wait.h>		/* waitpid(), WIFEXITED(),
				   WEXITSTATUS() */
#include <errno.h>		/* errno */
#include <argp.h>		/* struct argp_option,
				   struct argp_state, struct argp,
				   argp_parse() */

struct process;

typedef struct process{
  pid_t pid;
  int fd;
  char *buffer;
  size_t buffer_size;
  size_t buffer_length;
  struct process *next;
} process;

typedef struct plugin{
  char *name;			/* can be NULL or any plugin name */
  char **argv;
  int argc;
  bool disabled;
  struct plugin *next;
} plugin;

plugin *getplugin(char *name, plugin **plugin_list){
  for (plugin *p = *plugin_list; p != NULL; p = p->next){
    if ((p->name == name)
	or (p->name and name and (strcmp(p->name, name) == 0))){
      return p;
    }
  }
  /* Create a new plugin */
  plugin *new_plugin = malloc(sizeof(plugin));
  if (new_plugin == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  new_plugin->name = name;
  new_plugin->argv = malloc(sizeof(char *) * 2);
  if (new_plugin->argv == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  new_plugin->argv[0] = name;
  new_plugin->argv[1] = NULL;
  new_plugin->argc = 1;
  new_plugin->disabled = false;
  new_plugin->next = *plugin_list;
  /* Append the new plugin to the list */
  *plugin_list = new_plugin;
  return new_plugin;
}

void addargument(plugin *p, char *arg){
  p->argv[p->argc] = arg;
  p->argv = realloc(p->argv, sizeof(char *) * (size_t)(p->argc + 2));
  if (p->argv == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  p->argc++;
  p->argv[p->argc] = NULL;
}

/*
 * Based on the example in the GNU LibC manual chapter 13.13 "File
 * Descriptor Flags".
 * *Note File Descriptor Flags:(libc)Descriptor Flags.
 */
int set_cloexec_flag(int fd)
{
  int ret = fcntl(fd, F_GETFD, 0);
  /* If reading the flags failed, return error indication now. */
  if(ret < 0){
    return ret;
  }
  /* Store modified flag word in the descriptor. */
  return fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
}


#define BUFFER_SIZE 256

const char *argp_program_version =
  "plugbasedclient 0.9";
const char *argp_program_bug_address =
  "<mandos@fukt.bsnet.se>";

int main(int argc, char *argv[]){
  const char *plugindir = "/conf/conf.d/mandos/plugins.d";
  size_t d_name_len;
  DIR *dir;
  struct dirent *dirst;
  struct stat st;
  fd_set rfds_all;
  int ret, maxfd = 0;
  process *process_list = NULL;
  bool debug = false;
  int exitstatus = EXIT_SUCCESS;
  
  /* The options we understand. */
  struct argp_option options[] = {
    { .name = "global-options", .key = 'g',
      .arg = "OPTION[,OPTION[,...]]",
      .doc = "Options passed to all plugins" },
    { .name = "options-for", .key = 'o',
      .arg = "PLUGIN:OPTION[,OPTION[,...]]",
      .doc = "Options passed only to specified plugin" },
    { .name = "disable", .key = 'd',
      .arg = "PLUGIN",
      .doc = "Disable a specific plugin", .group = 1 },
    { .name = "plugin-dir", .key = 128,
      .arg = "DIRECTORY",
      .doc = "Specify a different plugin directory", .group = 2 },
    { .name = "debug", .key = 129,
      .doc = "Debug mode", .group = 3 },
    { .name = NULL }
  };
  
  error_t parse_opt (int key, char *arg, struct argp_state *state) {
       /* Get the INPUT argument from `argp_parse', which we
          know is a pointer to our plugin list pointer. */
    plugin **plugins = state->input;
    switch (key) {
    case 'g':
      if (arg != NULL){
	char *p = strtok(arg, ",");
	do{
	  addargument(getplugin(NULL, plugins), p);
	  p = strtok(NULL, ",");
	} while (p);
      }
      break;
    case 'o':
      if (arg != NULL){
	char *name = strtok(arg, ":");
	char *p = strtok(NULL, ":");
	if(p){
	  p = strtok(p, ",");
	  do{
	    addargument(getplugin(name, plugins), p);
	    p = strtok(NULL, ",");
	  } while (p);
	}
      }
      break;
    case 'd':
      if (arg != NULL){
	getplugin(arg, plugins)->disabled = true;
      }
      break;
    case 128:
      plugindir = arg;
      break;
    case 129:
      debug = true;
      break;
    case ARGP_KEY_ARG:
      argp_usage (state);
      break;
    case ARGP_KEY_END:
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return 0;
  }
  
  plugin *plugin_list = NULL;
  
  struct argp argp = { .options = options, .parser = parse_opt,
		       .args_doc = "",
		       .doc = "Mandos plugin runner -- Run plugins" };
  
  argp_parse (&argp, argc, argv, 0, 0, &plugin_list);
  
  if(debug){
    for(plugin *p = plugin_list; p != NULL; p=p->next){
      fprintf(stderr, "Plugin: %s has %d arguments\n",
	      p->name ? p->name : "Global", p->argc - 1);
      for(char **a = p->argv; *a != NULL; a++){
	fprintf(stderr, "\tArg: %s\n", *a);
      }
    }
  }
  
  dir = opendir(plugindir);
  if(dir == NULL){
    perror("Could not open plugin dir");
    exitstatus = EXIT_FAILURE;
    goto end;
  }
  /* Set the FD_CLOEXEC flag on the directory, if possible */
  {
    int dir_fd = dirfd(dir);
    if(dir_fd >= 0){
      ret = set_cloexec_flag(dir_fd);
      if(ret < 0){
	perror("set_cloexec_flag");
	exitstatus = EXIT_FAILURE;
	goto end;
      }
    }
  }
  
  if(dir == NULL){
    fprintf(stderr, "Can not open directory\n");
    return EXIT_FAILURE;
  }
  
  FD_ZERO(&rfds_all);
  
  while(true){
    dirst = readdir(dir);
    
    // All directory entries have been processed
    if(dirst == NULL){
      break;
    }
    
    d_name_len = strlen(dirst->d_name);
    
    // Ignore dotfiles, backup files and other junk
    {
      bool bad_name = false;
      
      const char const *bad_prefixes[] = { ".", "#", NULL };
      
      const char const *bad_suffixes[] = { "~", "#", ".dpkg-new",
					   ".dpkg-old",
					   ".dpkg-divert", NULL };
      for(const char **pre = bad_prefixes; *pre != NULL; pre++){
	size_t pre_len = strlen(*pre);
	if((d_name_len >= pre_len)
	   and strncmp((dirst->d_name), *pre, pre_len) == 0){
	  if(debug){
	    fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		    " with bad prefix %s\n", dirst->d_name, *pre);
	  }
	  bad_name = true;
	  break;
	}
      }
      
      if(bad_name){
	continue;
      }
      
      for(const char **suf = bad_suffixes; *suf != NULL; suf++){
	size_t suf_len = strlen(*suf);
	if((d_name_len >= suf_len)
	   and (strcmp((dirst->d_name)+d_name_len-suf_len, *suf)
		== 0)){
	  if(debug){
	    fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		    " with bad suffix %s\n", dirst->d_name, *suf);
	  }
	  bad_name = true;
	  break;
	}
      }
      
      if(bad_name){
	continue;
      }
    }
    
    char *filename = malloc(d_name_len + strlen(plugindir) + 2);
    if (filename == NULL){
      perror("malloc");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    strcpy(filename, plugindir);
    strcat(filename, "/");
    strcat(filename, dirst->d_name);    

    stat(filename, &st);

    if (not S_ISREG(st.st_mode)	or (access(filename, X_OK) != 0)){
      if(debug){
	fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		" with bad type or mode\n", filename);
      }
      continue;
    }
    if(getplugin(dirst->d_name, &plugin_list)->disabled){
      if(debug){
	fprintf(stderr, "Ignoring disabled plugin \"%s\"\n",
		dirst->d_name);
      }
      continue;
    }
    plugin *p = getplugin(dirst->d_name, &plugin_list);
    {
      /* Add global arguments to argument list for this plugin */
      plugin *g = getplugin(NULL, &plugin_list);
      for(char **a = g->argv + 1; *a != NULL; a++){
	addargument(p, *a);
      }
    }
    int pipefd[2]; 
    ret = pipe(pipefd);
    if (ret == -1){
      perror("pipe");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    ret = set_cloexec_flag(pipefd[0]);
    if(ret < 0){
      perror("set_cloexec_flag");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    ret = set_cloexec_flag(pipefd[1]);
    if(ret < 0){
      perror("set_cloexec_flag");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    // Starting a new process to be watched
    pid_t pid = fork();
    if(pid == 0){
      /* this is the child process */
      dup2(pipefd[1], STDOUT_FILENO); /* replace our stdout */
      
      if(dirfd(dir) < 0){
	/* If dir has no file descriptor, we could not set FD_CLOEXEC
	   and must close it manually  */
	closedir(dir);
      }
      if(execv(filename, p->argv) < 0){
	perror("execv");
	_exit(EXIT_FAILURE);
      }
      /* no return */
    }
    /* parent process */
    close(pipefd[1]);		/* close unused write end of pipe */
    process *new_process = malloc(sizeof(process));
    if (new_process == NULL){
      perror("malloc");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    
    *new_process = (struct process){ .pid = pid,
				     .fd = pipefd[0],
				     .next = process_list };
    FD_SET(new_process->fd, &rfds_all);
    
    if (maxfd < new_process->fd){
      maxfd = new_process->fd;
    }
    
    //List handling
    process_list = new_process;
  }
  
  /* Free the plugin list */
  for(plugin *next; plugin_list != NULL; plugin_list = next){
    next = plugin_list->next;
    free(plugin_list->argv);
    free(plugin_list);
  }
  
  closedir(dir);
  
  if (process_list == NULL){
    fprintf(stderr, "No plugin processes started, exiting\n");
    return EXIT_FAILURE;
  }
  while(true){
    fd_set rfds = rfds_all;
    int select_ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
    if (select_ret == -1){
      perror("select");
      exitstatus = EXIT_FAILURE;
      goto end;
    }
    for(process *proc = process_list; proc ; proc = proc->next){
      if(not FD_ISSET(proc->fd, &rfds)){
	continue;
      }
      if(proc->buffer_length + BUFFER_SIZE > proc->buffer_size){
	proc->buffer = realloc(proc->buffer, proc->buffer_size
			       + (size_t) BUFFER_SIZE);
	if (proc->buffer == NULL){
	  perror("malloc");
	  exitstatus = EXIT_FAILURE;
	  goto end;
	}
	proc->buffer_size += BUFFER_SIZE;
      }
      ret = read(proc->fd, proc->buffer + proc->buffer_length,
		 BUFFER_SIZE);
      if(ret < 0){
	/* Read error from this process; ignore it */
	continue;
      }
      proc->buffer_length += (size_t) ret;
      if(ret == 0){
	/* got EOF */
	/* wait for process exit */
	int status;
	waitpid(proc->pid, &status, 0);
	if(not WIFEXITED(status) or WEXITSTATUS(status) != 0){
	  FD_CLR(proc->fd, &rfds_all);
	  continue;
	}
	for(size_t written = 0;
	    written < proc->buffer_length; written += (size_t)ret){
	  ret = TEMP_FAILURE_RETRY(write(STDOUT_FILENO,
					 proc->buffer + written,
					 proc->buffer_length
					 - written));
	  if(ret < 0){
	    perror("write");
	    exitstatus = EXIT_FAILURE;
	    goto end;
	  }
	}
	goto end;
      }
    }
  }
  
 end:
  for(process *next; process_list != NULL; process_list = next){
    close(process_list->fd);
    kill(process_list->pid, SIGTERM);
    free(process_list->buffer);
    free(process_list);
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
  return exitstatus;
}
