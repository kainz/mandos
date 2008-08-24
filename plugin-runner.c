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

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY(), getline(),
				   asprintf() */
#include <stddef.h>		/* size_t, NULL */
#include <stdlib.h>		/* malloc(), exit(), EXIT_FAILURE,
				   EXIT_SUCCESS, realloc() */
#include <stdbool.h>		/* bool, true, false */
#include <stdio.h>		/* perror, popen(), fileno(),
				   fprintf(), stderr, STDOUT_FILENO */
#include <sys/types.h>	        /* DIR, opendir(), stat(), struct
				   stat, waitpid(), WIFEXITED(),
				   WEXITSTATUS(), wait(), pid_t,
				   uid_t, gid_t, getuid(), getgid(),
				   dirfd() */
#include <sys/select.h>		/* fd_set, select(), FD_ZERO(),
				   FD_SET(), FD_ISSET(), FD_CLR */
#include <sys/wait.h>		/* wait(), waitpid(), WIFEXITED(),
				   WEXITSTATUS() */
#include <sys/stat.h>		/* struct stat, stat(), S_ISREG() */
#include <iso646.h>		/* and, or, not */
#include <dirent.h>		/* DIR, struct dirent, opendir(),
				   readdir(), closedir(), dirfd() */
#include <unistd.h>		/* struct stat, stat(), S_ISREG(),
				   fcntl(), setuid(), setgid(),
				   F_GETFD, F_SETFD, FD_CLOEXEC,
				   access(), pipe(), fork(), close()
				   dup2, STDOUT_FILENO, _exit(),
				   execv(), write(), read(),
				   close() */
#include <fcntl.h>		/* fcntl(), F_GETFD, F_SETFD,
				   FD_CLOEXEC */
#include <string.h>		/* strsep, strlen(), asprintf() */
#include <errno.h>		/* errno */
#include <argp.h>		/* struct argp_option, struct
				   argp_state, struct argp,
				   argp_parse(), ARGP_ERR_UNKNOWN,
				   ARGP_KEY_END, ARGP_KEY_ARG, error_t */
#include <signal.h> 		/* struct sigaction, sigemptyset(),
				   sigaddset(), sigaction(),
				   sigprocmask(), SIG_BLOCK, SIGCHLD,
				   SIG_UNBLOCK, kill() */
#include <errno.h>		/* errno, EBADF */

#define BUFFER_SIZE 256
#define ARGFILE "/conf/conf.d/mandos/plugin-runner.conf"

const char *argp_program_version = "plugin-runner 1.0";
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";

struct process;

typedef struct process{
  pid_t pid;
  int fd;
  char *buffer;
  size_t buffer_size;
  size_t buffer_length;
  bool eof;
  bool completed;
  int status;
  struct process *next;
} process;

typedef struct plugin{
  char *name;			/* can be NULL or any plugin name */
  char **argv;
  int argc;
  char **environ;
  int envc;
  bool disabled;
  struct plugin *next;
} plugin;

static plugin *getplugin(char *name, plugin **plugin_list){
  for (plugin *p = *plugin_list; p != NULL; p = p->next){
    if ((p->name == name)
	or (p->name and name and (strcmp(p->name, name) == 0))){
      return p;
    }
  }
  /* Create a new plugin */
  plugin *new_plugin = malloc(sizeof(plugin));
  if (new_plugin == NULL){
    return NULL;
  }
  char *copy_name = NULL;
  if(name != NULL){
    copy_name = strdup(name);
    if(copy_name == NULL){
      return NULL;
    }
  }
  
  *new_plugin = (plugin) { .name = copy_name,
			   .argc = 1,
			   .envc = 0,
			   .disabled = false,
			   .next = *plugin_list };
  
  new_plugin->argv = malloc(sizeof(char *) * 2);
  if (new_plugin->argv == NULL){
    free(copy_name);
    free(new_plugin);
    return NULL;
  }
  new_plugin->argv[0] = copy_name;
  new_plugin->argv[1] = NULL;

  new_plugin->environ = malloc(sizeof(char *));
  if(new_plugin->environ == NULL){
    free(copy_name);
    free(new_plugin->argv);
    free(new_plugin);
    return NULL;
  }
  new_plugin->environ[0] = NULL;
  /* Append the new plugin to the list */
  *plugin_list = new_plugin;
  return new_plugin;
}

/* Helper function for add_argument and add_environment */
static bool add_to_char_array(const char *new, char ***array,
			      int *len){
  /* Resize the pointed-to array to hold one more pointer */
  *array = realloc(*array, sizeof(char *)
		   * (size_t) ((*len) + 2));
  /* Malloc check */
  if(*array == NULL){
    return false;
  }
  /* Make a copy of the new string */
  char *copy = strdup(new);
  if(copy == NULL){
    return false;
  }
  /* Insert the copy */
  (*array)[*len] = copy;
  (*len)++;
  /* Add a new terminating NULL pointer to the last element */
  (*array)[*len] = NULL;
  return true;
}

/* Add to a plugin's argument vector */
static bool add_argument(plugin *p, const char *arg){
  if(p == NULL){
    return false;
  }
  return add_to_char_array(arg, &(p->argv), &(p->argc));
}

/* Add to a plugin's environment */
static bool add_environment(plugin *p, const char *def){
  if(p == NULL){
    return false;
  }
  return add_to_char_array(def, &(p->environ), &(p->envc));
}


/*
 * Based on the example in the GNU LibC manual chapter 13.13 "File
 * Descriptor Flags".
 * *Note File Descriptor Flags:(libc)Descriptor Flags.
 */
static int set_cloexec_flag(int fd)
{
  int ret = fcntl(fd, F_GETFD, 0);
  /* If reading the flags failed, return error indication now. */
  if(ret < 0){
    return ret;
  }
  /* Store modified flag word in the descriptor. */
  return fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
}

process *process_list = NULL;

/* Mark processes as completed when it exits, and save its exit
   status. */
void handle_sigchld(__attribute__((unused)) int sig){
  process *proc = process_list;
  while(true){
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if(pid == 0){
      break;
    }
    if(pid == -1){
      if (errno != ECHILD){
	perror("waitpid");
      }
      return;
    }

    while(proc != NULL and proc->pid != pid){
      proc = proc->next;
    }
    if(proc == NULL){
      /* Process not found in process list */
      continue;
    }
    proc->status = status;
    proc->completed = true;
  }
}

bool print_out_password(const char *buffer, size_t length){
  ssize_t ret;
  if(length>0 and buffer[length-1] == '\n'){
    length--;
  }
  for(size_t written = 0; written < length; written += (size_t)ret){
    ret = TEMP_FAILURE_RETRY(write(STDOUT_FILENO, buffer + written,
				   length - written));
    if(ret < 0){
      return false;
    }
  }
  return true;
}

char **add_to_argv(char **argv, int *argc, char *arg){
  if (argv == NULL){
    *argc = 1;
    argv = malloc(sizeof(char*) * 2);
    if(argv == NULL){
      return NULL;
    }
    argv[0] = NULL; 	/* Will be set to argv[0] in main before parsing */
    argv[1] = NULL;
  }
  *argc += 1;
  argv = realloc(argv, sizeof(char *)
		  * ((unsigned int) *argc + 1));
  if(argv == NULL){
    return NULL;
  }
  argv[*argc-1] = arg;
  argv[*argc] = NULL;
  return argv;
}

static void free_plugin_list(plugin *plugin_list){
  for(plugin *next; plugin_list != NULL; plugin_list = next){
    next = plugin_list->next;
    for(char **arg = plugin_list->argv; *arg != NULL; arg++){
      free(*arg);
    }
    free(plugin_list->argv);
    for(char **env = plugin_list->environ; *env != NULL; env++){
      free(*env);
    }
    free(plugin_list->environ);
    free(plugin_list);
  }
}

int main(int argc, char *argv[]){
  const char *plugindir = "/lib/mandos/plugins.d";
  const char *argfile = ARGFILE;
  FILE *conffp;
  size_t d_name_len;
  DIR *dir = NULL;
  struct dirent *dirst;
  struct stat st;
  fd_set rfds_all;
  int ret, maxfd = 0;
  uid_t uid = 65534;
  gid_t gid = 65534;
  bool debug = false;
  int exitstatus = EXIT_SUCCESS;
  struct sigaction old_sigchld_action;
  struct sigaction sigchld_action = { .sa_handler = handle_sigchld,
				      .sa_flags = SA_NOCLDSTOP };
  char **custom_argv = NULL;
  int custom_argc = 0;
  
  /* Establish a signal handler */
  sigemptyset(&sigchld_action.sa_mask);
  ret = sigaddset(&sigchld_action.sa_mask, SIGCHLD);
  if(ret == -1){
    perror("sigaddset");
    exitstatus = EXIT_FAILURE;
    goto fallback;
  }
  ret = sigaction(SIGCHLD, &sigchld_action, &old_sigchld_action);
  if(ret == -1){
    perror("sigaction");
    exitstatus = EXIT_FAILURE;
    goto fallback;
  }
  
  /* The options we understand. */
  struct argp_option options[] = {
    { .name = "global-options", .key = 'g',
      .arg = "OPTION[,OPTION[,...]]",
      .doc = "Options passed to all plugins" },
    { .name = "global-envs", .key = 'e',
      .arg = "VAR=value",
      .doc = "Environment variable passed to all plugins" },
    { .name = "options-for", .key = 'o',
      .arg = "PLUGIN:OPTION[,OPTION[,...]]",
      .doc = "Options passed only to specified plugin" },
    { .name = "envs-for", .key = 'f',
      .arg = "PLUGIN:ENV=value",
      .doc = "Environment variable passed to specified plugin" },
    { .name = "disable", .key = 'd',
      .arg = "PLUGIN",
      .doc = "Disable a specific plugin", .group = 1 },
    { .name = "plugin-dir", .key = 128,
      .arg = "DIRECTORY",
      .doc = "Specify a different plugin directory", .group = 2 },
    { .name = "userid", .key = 129,
      .arg = "ID", .flags = 0,
      .doc = "User ID the plugins will run as", .group = 2 },
    { .name = "groupid", .key = 130,
      .arg = "ID", .flags = 0,
      .doc = "Group ID the plugins will run as", .group = 2 },
    { .name = "debug", .key = 131,
      .doc = "Debug mode", .group = 3 },
    { .name = NULL }
  };
  
  error_t parse_opt (int key, char *arg, struct argp_state *state) {
    /* Get the INPUT argument from `argp_parse', which we know is a
       pointer to our plugin list pointer. */
    plugin **plugins = state->input;
    switch (key) {
    case 'g':
      if (arg != NULL){
	char *p;
	while((p = strsep(&arg, ",")) != NULL){
	  if(p[0] == '\0'){
	    continue;
	  }
	  if(not add_argument(getplugin(NULL, plugins), p)){
	    perror("add_argument");
	    return ARGP_ERR_UNKNOWN;
	  }
	}
      }
      break;
    case 'e':
      if(arg == NULL){
	break;
      }
      {
	char *envdef = strdup(arg);
	if(envdef == NULL){
	  break;
	}
	if(not add_environment(getplugin(NULL, plugins), envdef)){
	  perror("add_environment");
	}
      }
      break;
    case 'o':
      if (arg != NULL){
	char *p_name = strsep(&arg, ":");
	if(p_name[0] == '\0'){
	  break;
	}
	char *opt = strsep(&arg, ":");
	if(opt[0] == '\0'){
	  break;
	}
	if(opt != NULL){
	  char *p;
	  while((p = strsep(&opt, ",")) != NULL){
	    if(p[0] == '\0'){
	      continue;
	    }
	    if(not add_argument(getplugin(p_name, plugins), p)){
	      perror("add_argument");
	      return ARGP_ERR_UNKNOWN;
	    }
	  }
	}
      }
      break;
    case 'f':
      if(arg == NULL){
	break;
      }
      {
	char *envdef = strchr(arg, ':');
	if(envdef == NULL){
	  break;
	}
	char *p_name = strndup(arg, (size_t) (envdef-arg));
	if(p_name == NULL){
	  break;
	}
	envdef++;
	if(not add_environment(getplugin(p_name, plugins), envdef)){
	  perror("add_environment");
	}
      }
      break;
    case 'd':
      if (arg != NULL){
	plugin *p = getplugin(arg, plugins);
	if(p == NULL){
	  return ARGP_ERR_UNKNOWN;
	}
	p->disabled = true;
      }
      break;
    case 128:
      plugindir = arg;
      break;
    case 129:
      uid = (uid_t)strtol(arg, NULL, 10);
      break;
    case 130:
      gid = (gid_t)strtol(arg, NULL, 10);
      break;
    case 131:
      debug = true;
      break;
    case ARGP_KEY_ARG:
      fprintf(stderr, "Ignoring unknown argument \"%s\"\n", arg);
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
		       .args_doc = "[+PLUS_SEPARATED_OPTIONS]",
		       .doc = "Mandos plugin runner -- Run plugins" };
  
  ret = argp_parse (&argp, argc, argv, 0, 0, &plugin_list);
  if (ret == ARGP_ERR_UNKNOWN){
    fprintf(stderr, "Unknown error while parsing arguments\n");
    exitstatus = EXIT_FAILURE;
    goto fallback;
  }

  conffp = fopen(argfile, "r");
  if(conffp != NULL){
    char *org_line = NULL;
    char *p, *arg, *new_arg, *line;
    size_t size = 0;
    ssize_t sret;
    const char whitespace_delims[] = " \r\t\f\v\n";
    const char comment_delim[] = "#";

    while(true){
      sret = getline(&org_line, &size, conffp);
      if(sret == -1){
	break;
      }

      line = org_line;
      arg = strsep(&line, comment_delim);
      while((p = strsep(&arg, whitespace_delims)) != NULL){
	if(p[0] == '\0'){
	  continue;
	}
	new_arg = strdup(p);
	custom_argv = add_to_argv(custom_argv, &custom_argc, new_arg);
	if (custom_argv == NULL){
	  perror("add_to_argv");
	  exitstatus = EXIT_FAILURE;
	  goto fallback;
	}
      }
    }
    free(org_line);
  } else{
    /* Check for harmful errors and go to fallback. Other errors might
       not affect opening plugins */
    if (errno == EMFILE or errno == ENFILE or errno == ENOMEM){
      perror("fopen");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
  }

  if(custom_argv != NULL){
    custom_argv[0] = argv[0];
    ret = argp_parse (&argp, custom_argc, custom_argv, 0, 0, &plugin_list);
    if (ret == ARGP_ERR_UNKNOWN){
      fprintf(stderr, "Unknown error while parsing arguments\n");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
  }
  
  if(debug){
    for(plugin *p = plugin_list; p != NULL; p=p->next){
      fprintf(stderr, "Plugin: %s has %d arguments\n",
	      p->name ? p->name : "Global", p->argc - 1);
      for(char **a = p->argv; *a != NULL; a++){
	fprintf(stderr, "\tArg: %s\n", *a);
      }
      fprintf(stderr, "...and %u environment variables\n", p->envc);
      for(char **a = p->environ; *a != NULL; a++){
	fprintf(stderr, "\t%s\n", *a);
      }
    }
  }
  
  ret = setuid(uid);
  if (ret == -1){
    perror("setuid");
  }
  
  setgid(gid);
  if (ret == -1){
    perror("setgid");
  }
  
  dir = opendir(plugindir);
  if(dir == NULL){
    perror("Could not open plugin dir");
    exitstatus = EXIT_FAILURE;
    goto fallback;
  }
  
  /* Set the FD_CLOEXEC flag on the directory, if possible */
  {
    int dir_fd = dirfd(dir);
    if(dir_fd >= 0){
      ret = set_cloexec_flag(dir_fd);
      if(ret < 0){
	perror("set_cloexec_flag");
	exitstatus = EXIT_FAILURE;
	goto fallback;
      }
    }
  }
  
  FD_ZERO(&rfds_all);
  
  while(true){
    dirst = readdir(dir);
    
    // All directory entries have been processed
    if(dirst == NULL){
      if (errno == EBADF){
	perror("readdir");
	exitstatus = EXIT_FAILURE;
	goto fallback;
      }
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

    char *filename;
    ret = asprintf(&filename, "%s/%s", plugindir, dirst->d_name);
    if(ret < 0){
      perror("asprintf");
      continue;
    }
    
    ret = stat(filename, &st);
    if (ret == -1){
      perror("stat");
      free(filename);
      continue;
    }
    
    if (not S_ISREG(st.st_mode)	or (access(filename, X_OK) != 0)){
      if(debug){
	fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		" with bad type or mode\n", filename);
      }
      free(filename);
      continue;
    }
    plugin *p = getplugin(dirst->d_name, &plugin_list);
    if(p == NULL){
      perror("getplugin");
      free(filename);
      continue;
    }
    if(p->disabled){
      if(debug){
	fprintf(stderr, "Ignoring disabled plugin \"%s\"\n",
		dirst->d_name);
      }
      free(filename);
      continue;
    }
    {
      /* Add global arguments to argument list for this plugin */
      plugin *g = getplugin(NULL, &plugin_list);
      if(g != NULL){
	for(char **a = g->argv + 1; *a != NULL; a++){
	  if(not add_argument(p, *a)){
	    perror("add_argument");
	  }
	}
	/* Add global environment variables */
	for(char **e = g->environ; *e != NULL; e++){
	  if(not add_environment(p, *e)){
	    perror("add_environment");
	  }
	}
      }
    }
    /* If this plugin has any environment variables, we will call
       using execve and need to duplicate the environment from this
       process, too. */
    if(p->environ[0] != NULL){
      for(char **e = environ; *e != NULL; e++){
	char *copy = strdup(*e);
	if(copy == NULL){
	  perror("strdup");
	  continue;
	}
	if(not add_environment(p, copy)){
	  perror("add_environment");
	}
      }
    }
    
    int pipefd[2];
    ret = pipe(pipefd);
    if (ret == -1){
      perror("pipe");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    ret = set_cloexec_flag(pipefd[0]);
    if(ret < 0){
      perror("set_cloexec_flag");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    ret = set_cloexec_flag(pipefd[1]);
    if(ret < 0){
      perror("set_cloexec_flag");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    /* Block SIGCHLD until process is safely in process list */
    ret = sigprocmask (SIG_BLOCK, &sigchld_action.sa_mask, NULL);
    if(ret < 0){
      perror("sigprocmask");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    // Starting a new process to be watched
    pid_t pid = fork();
    if(pid == -1){
      perror("fork");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    if(pid == 0){
      /* this is the child process */
      ret = sigaction(SIGCHLD, &old_sigchld_action, NULL);
      if(ret < 0){
	perror("sigaction");
	_exit(EXIT_FAILURE);
      }
      ret = sigprocmask (SIG_UNBLOCK, &sigchld_action.sa_mask, NULL);
      if(ret < 0){
	perror("sigprocmask");
	_exit(EXIT_FAILURE);
      }

      ret = dup2(pipefd[1], STDOUT_FILENO); /* replace our stdout */
      if(ret == -1){
	perror("dup2");
	_exit(EXIT_FAILURE);
      }
      
      if(dirfd(dir) < 0){
	/* If dir has no file descriptor, we could not set FD_CLOEXEC
	   above and must now close it manually here. */
	closedir(dir);
      }
      if(p->environ[0] == NULL){
	if(execv(filename, p->argv) < 0){
	  perror("execv");
	  _exit(EXIT_FAILURE);
	}
      } else {
	if(execve(filename, p->argv, p->environ) < 0){
	  perror("execve");
	  _exit(EXIT_FAILURE);
	}
      }
      /* no return */
    }
    /* parent process */
    free(filename);
    close(pipefd[1]);		/* close unused write end of pipe */
    process *new_process = malloc(sizeof(process));
    if (new_process == NULL){
      perror("malloc");
      ret = sigprocmask (SIG_UNBLOCK, &sigchld_action.sa_mask, NULL);
      if(ret < 0){
	perror("sigprocmask");
      }
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    
    *new_process = (struct process){ .pid = pid,
				     .fd = pipefd[0],
				     .next = process_list };
    // List handling
    process_list = new_process;
    /* Unblock SIGCHLD so signal handler can be run if this process
       has already completed */
    ret = sigprocmask (SIG_UNBLOCK, &sigchld_action.sa_mask, NULL);
    if(ret < 0){
      perror("sigprocmask");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    
    FD_SET(new_process->fd, &rfds_all);
    
    if (maxfd < new_process->fd){
      maxfd = new_process->fd;
    }
    
  }
  
  free_plugin_list(plugin_list);
  plugin_list = NULL;
  
  closedir(dir);
  dir = NULL;
    
  if (process_list == NULL){
    fprintf(stderr, "No plugin processes started. Incorrect plugin"
	    " directory?\n");
    process_list = NULL;
  }
  while(process_list){
    fd_set rfds = rfds_all;
    int select_ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
    if (select_ret == -1){
      perror("select");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    /* OK, now either a process completed, or something can be read
       from one of them */
    for(process *proc = process_list; proc ; proc = proc->next){
      /* Is this process completely done? */
      if(proc->eof and proc->completed){
	/* Only accept the plugin output if it exited cleanly */
	if(not WIFEXITED(proc->status)
	   or WEXITSTATUS(proc->status) != 0){
	  /* Bad exit by plugin */
	  if(debug){
	    if(WIFEXITED(proc->status)){
	      fprintf(stderr, "Plugin %u exited with status %d\n",
		      (unsigned int) (proc->pid),
		      WEXITSTATUS(proc->status));
	    } else if(WIFSIGNALED(proc->status)) {
	      fprintf(stderr, "Plugin %u killed by signal %d\n",
		      (unsigned int) (proc->pid),
		      WTERMSIG(proc->status));
	    } else if(WCOREDUMP(proc->status)){
	      fprintf(stderr, "Plugin %d dumped core\n",
		      (unsigned int) (proc->pid));
	    }
	  }
	  /* Remove the plugin */
	  FD_CLR(proc->fd, &rfds_all);
	  /* Block signal while modifying process_list */
	  ret = sigprocmask (SIG_BLOCK, &sigchld_action.sa_mask, NULL);
	  if(ret < 0){
	    perror("sigprocmask");
	    exitstatus = EXIT_FAILURE;
	    goto fallback;
	  }
	  /* Delete this process entry from the list */
	  if(process_list == proc){
	    /* First one - simple */
	    process_list = proc->next;
	  } else {
	    /* Second one or later */
	    for(process *p = process_list; p != NULL; p = p->next){
	      if(p->next == proc){
		p->next = proc->next;
		break;
	      }
	    }
	  }
	  /* We are done modifying process list, so unblock signal */
	  ret = sigprocmask (SIG_UNBLOCK, &sigchld_action.sa_mask,
			     NULL);
	  if(ret < 0){
	    perror("sigprocmask");
	  }
	  free(proc->buffer);
	  free(proc);
	  /* We deleted this process from the list, so we can't go
	     proc->next.  Therefore, start over from the beginning of
	     the process list */
	  break;
	}
	/* This process exited nicely, so print its buffer */

	bool bret = print_out_password(proc->buffer, proc->buffer_length);
	if(not bret){
	  perror("print_out_password");
	  exitstatus = EXIT_FAILURE;
	}
	goto fallback;
      }
      /* This process has not completed.  Does it have any output? */
      if(proc->eof or not FD_ISSET(proc->fd, &rfds)){
	/* This process had nothing to say at this time */
	continue;
      }
      /* Before reading, make the process' data buffer large enough */
      if(proc->buffer_length + BUFFER_SIZE > proc->buffer_size){
	proc->buffer = realloc(proc->buffer, proc->buffer_size
			       + (size_t) BUFFER_SIZE);
	if (proc->buffer == NULL){
	  perror("malloc");
	  exitstatus = EXIT_FAILURE;
	  goto fallback;
	}
	proc->buffer_size += BUFFER_SIZE;
      }
      /* Read from the process */
      ret = read(proc->fd, proc->buffer + proc->buffer_length,
		 BUFFER_SIZE);
      if(ret < 0){
	/* Read error from this process; ignore the error */
	continue;
      }
      if(ret == 0){
	/* got EOF */
	proc->eof = true;
      } else {
	proc->buffer_length += (size_t) ret;
      }
    }
  }


 fallback:
  
  if(process_list == NULL or exitstatus != EXIT_SUCCESS){
    /* Fallback if all plugins failed, none are found or an error occured */
    bool bret;
    fprintf(stderr, "Going to fallback mode using getpass(3)\n");
    char *passwordbuffer = getpass("Password: ");
    bret = print_out_password(passwordbuffer, strlen(passwordbuffer));
    if(not bret){
      perror("print_out_password");
      exitstatus = EXIT_FAILURE;
    }
  }
  
  /* Restore old signal handler */
  ret = sigaction(SIGCHLD, &old_sigchld_action, NULL);
  if(ret == -1){
    perror("sigaction");
    exitstatus = EXIT_FAILURE;
  }

  if(custom_argv != NULL){
    for(char **arg = custom_argv; *arg != NULL; arg++){
      free(*arg);
    }
    free(custom_argv);
  }
  free_plugin_list(plugin_list);
  
  if(dir != NULL){
    closedir(dir);
  }
  
  /* Free the process list and kill the processes */
  for(process *next; process_list != NULL; process_list = next){
    next = process_list->next;
    close(process_list->fd);
    ret = kill(process_list->pid, SIGTERM);
    if(ret == -1 and errno != ESRCH){
      /* set-uid proccesses migth not get closed */
      perror("kill");
    }
    free(process_list->buffer);
    free(process_list);
  }
  
  /* Wait for any remaining child processes to terminate */
  do{
    ret = wait(NULL);
  } while(ret >= 0);
  if(errno != ECHILD){
    perror("wait");
  }
  
  return exitstatus;
}
