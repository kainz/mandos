/*  -*- coding: utf-8 -*- */
/*
 * Mandos plugin runner - Run Mandos plugins
 *
 * Copyright © 2007-2008 Teddy Hogeborn and Björn Påhlsson.
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
 * Contact the authors at <https://www.fukt.bsnet.se/~belorn/> and
 * <https://www.fukt.bsnet.se/~teddy/>.
 */

#define _FORTIFY_SOURCE 2

#include <stdio.h>	/* popen, fileno */
#include <iso646.h>	/* and, or, not */
#include <sys/types.h>	/* DIR, opendir, stat, struct stat, waitpid,
			   WIFEXITED, WEXITSTATUS, wait */
#include <sys/wait.h>	/* wait */
#include <dirent.h>	/* DIR, opendir */
#include <sys/stat.h>	/* stat, struct stat */
#include <unistd.h>	/* stat, struct stat, chdir */
#include <stdlib.h>	/* EXIT_FAILURE */
#include <sys/select.h>	/* fd_set, select, FD_ZERO, FD_SET,
			   FD_ISSET */
#include <string.h>	/* strlen, strcpy, strcat */
#include <stdbool.h>	/* true */
#include <sys/wait.h>	/* waitpid, WIFEXITED, WEXITSTATUS */
#include <errno.h>	/* errno */
#include <argp.h>	/* argp */

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
  char *name; 		/* can be "global" and any plugin name */
  char **argv;
  int argc;
  bool disable;
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
  new_plugin->disable = false;
  new_plugin->next = *plugin_list;
  /* Append the new plugin to the list */
  *plugin_list = new_plugin;
  return new_plugin;
}

void addarguments(plugin *p, char *arg){
  p->argv[p->argc] = arg;
  p->argv = realloc(p->argv, sizeof(char *) * (size_t)(p->argc + 2));
  if (p->argv == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  p->argc++;
  p->argv[p->argc] = NULL;
}
	
#define BUFFER_SIZE 256

const char *argp_program_version =
  "plugbasedclient 0.9";
const char *argp_program_bug_address =
  "<mandos@fukt.bsnet.se>";
static char doc[] =
  "Mandos plugin runner -- Run Mandos plugins";
/* A description of the arguments we accept. */
static char args_doc[] = "";

int main(int argc, char *argv[]){
  const char *plugindir = "plugins.d";
  size_t d_name_len;
  DIR *dir;
  struct dirent *dirst;
  struct stat st;
  fd_set rfds_orig;
  int ret, maxfd = 0;
  process *process_list = NULL;

  /* The options we understand. */
  struct argp_option options[] = {
    { .name = "global-options", .key = 'g',
      .arg = "option[,option[,...]]", .flags = 0,
      .doc = "Options effecting all plugins" },
    { .name = "options-for", .key = 'o',
      .arg = "plugin:option[,option[,...]]", .flags = 0,
      .doc = "Options effecting only specified plugins" },
    { .name = "disable-plugin", .key = 'd',
      .arg = "Plugin[,Plugin[,...]]", .flags = 0,
      .doc = "Option to disable specififed plugins" },
    { .name = "plugin-dir", .key = 128,
      .arg = "Directory", .flags = 0,
      .doc = "Option to change directory to search for plugins" },
    { .name = NULL }
  };
  
  error_t parse_opt (int key, char *arg, struct argp_state *state) {
       /* Get the INPUT argument from `argp_parse', which we
          know is a pointer to our arguments structure. */
    plugin **plugins = state->input;
    switch (key) {
    case 'g':
      if (arg != NULL){
	char *p = strtok(arg, ",");
	do{
	  addarguments(getplugin(NULL, plugins), p);
	  p = strtok(NULL, ",");
	} while (p);
      }
      break;
    case 'o':
      if (arg != NULL){
	char *name = strtok(arg, ":");
	char *p = strtok(NULL, ":");
	p = strtok(p, ",");
	do{
	  addarguments(getplugin(name, plugins), p);
	  p = strtok(NULL, ",");
	} while (p);
      }
      break;
    case 'd':
      if (arg != NULL){
	char *p = strtok(arg, ",");
	do{
	  getplugin(p, plugins)->disable = true;
	  p = strtok(NULL, ",");
	} while (p);
      }
      break;
    case 128:
      plugindir = arg;
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
		       .args_doc = args_doc, .doc = doc };

  argp_parse (&argp, argc, argv, 0, 0, &plugin_list);

/*   for(plugin *p = plugin_list; p != NULL; p=p->next){ */
/*     fprintf(stderr, "Plugin: %s has %d arguments\n", p->name ? p->name : "Global", p->argc); */
/*     for(char **a = p->argv + 1; *a != NULL; a++){ */
/*       fprintf(stderr, "\tArg: %s\n", *a); */
/*     } */
/*   } */
  
/*   return 0; */

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

    char *filename = malloc(d_name_len + strlen(plugindir) + 2);
    strcpy(filename, plugindir);
    strcat(filename, "/");
    strcat(filename, dirst->d_name);    

    stat(filename, &st);

    if (S_ISREG(st.st_mode)
	and (access(filename, X_OK) == 0)
	and not (getplugin(dirst->d_name, &plugin_list)->disable)){
      // Starting a new process to be watched
      process *new_process = malloc(sizeof(process));
      int pipefd[2]; 
      ret = pipe(pipefd);
      if (ret == -1){
	perror(argv[0]);
	goto end;
      }
      new_process->pid = fork();
      if(new_process->pid == 0){
	/* this is the child process */
	closedir(dir);
	close(pipefd[0]);	/* close unused read end of pipe */
	dup2(pipefd[1], STDOUT_FILENO); /* replace our stdout */

	plugin *p = getplugin(dirst->d_name, &plugin_list);
	plugin *g = getplugin(NULL, &plugin_list);
	for(char **a = g->argv + 1; *a != NULL; a++){
	  addarguments(p, *a);
	}
	if(execv(filename, p->argv) < 0){
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
					      + (size_t) BUFFER_SIZE);
		if (process_itr->buffer == NULL){
		  perror(argv[0]);
		  goto end;
		}
		process_itr->buffer_size += BUFFER_SIZE;
	    }
	    ret = read(process_itr->fd, process_itr->buffer
		       + process_itr->buffer_length, BUFFER_SIZE);
	    if(ret < 0){
	      /* Read error from this process; ignore it */
	      continue;
	    }
	    process_itr->buffer_length += (size_t) ret;
	    if(ret == 0){
	      /* got EOF */
	      /* wait for process exit */
	      int status;
	      waitpid(process_itr->pid, &status, 0);
	      if(WIFEXITED(status) and WEXITSTATUS(status) == 0){
		for(size_t written = 0;
		    written < process_itr->buffer_length;){
		  ret = write(STDOUT_FILENO,
			      process_itr->buffer + written,
			      process_itr->buffer_length - written);
		  if(ret < 0){
		    perror(argv[0]);
		    goto end;
		  }
		  written += (size_t)ret;
		}
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
