/*  -*- coding: utf-8; mode: c; mode: orgtbl -*- */
/*
 * Mandos plugin runner - Run Mandos plugins
 *
 * Copyright © 2008-2017 Teddy Hogeborn
 * Copyright © 2008-2017 Björn Påhlsson
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

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY(), getline(),
				   O_CLOEXEC, pipe2() */
#include <stddef.h>		/* size_t, NULL */
#include <stdlib.h>		/* malloc(), exit(), EXIT_SUCCESS,
				   realloc() */
#include <stdbool.h>		/* bool, true, false */
#include <stdio.h>		/* fileno(), fprintf(),
				   stderr, STDOUT_FILENO, fclose() */
#include <sys/types.h>	        /* fstat(), struct stat, waitpid(),
				   WIFEXITED(), WEXITSTATUS(), wait(),
				   pid_t, uid_t, gid_t, getuid(),
				   getgid() */
#include <sys/select.h>		/* fd_set, select(), FD_ZERO(),
				   FD_SET(), FD_ISSET(), FD_CLR */
#include <sys/wait.h>		/* wait(), waitpid(), WIFEXITED(),
				   WEXITSTATUS(), WTERMSIG() */
#include <sys/stat.h>		/* struct stat, fstat(), S_ISREG() */
#include <iso646.h>		/* and, or, not */
#include <dirent.h>		/* struct dirent, scandirat() */
#include <unistd.h>		/* fcntl(), F_GETFD, F_SETFD,
				   FD_CLOEXEC, write(), STDOUT_FILENO,
				   struct stat, fstat(), close(),
				   setgid(), setuid(), S_ISREG(),
				   faccessat() pipe2(), fork(),
				   _exit(), dup2(), fexecve(), read()
				*/
#include <fcntl.h>		/* fcntl(), F_GETFD, F_SETFD,
				   FD_CLOEXEC, openat(), scandirat(),
				   pipe2() */
#include <string.h>		/* strsep, strlen(), strsignal(),
				   strcmp(), strncmp() */
#include <errno.h>		/* errno */
#include <argp.h>		/* struct argp_option, struct
				   argp_state, struct argp,
				   argp_parse(), ARGP_ERR_UNKNOWN,
				   ARGP_KEY_END, ARGP_KEY_ARG,
				   error_t */
#include <signal.h> 		/* struct sigaction, sigemptyset(),
				   sigaddset(), sigaction(),
				   sigprocmask(), SIG_BLOCK, SIGCHLD,
				   SIG_UNBLOCK, kill(), sig_atomic_t
				*/
#include <errno.h>		/* errno, EBADF */
#include <inttypes.h>		/* intmax_t, PRIdMAX, strtoimax() */
#include <sysexits.h>		/* EX_OSERR, EX_USAGE, EX_IOERR,
				   EX_CONFIG, EX_UNAVAILABLE, EX_OK */
#include <errno.h> 		/* errno */
#include <error.h>		/* error() */
#include <fnmatch.h>		/* fnmatch() */

#define BUFFER_SIZE 256

#define PDIR "/lib/mandos/plugins.d"
#define PHDIR "/lib/mandos/plugin-helpers"
#define AFILE "/conf/conf.d/mandos/plugin-runner.conf"

const char *argp_program_version = "plugin-runner " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";

typedef struct plugin{
  char *name;			/* can be NULL or any plugin name */
  char **argv;
  int argc;
  char **environ;
  int envc;
  bool disabled;
  
  /* Variables used for running processes*/
  pid_t pid;
  int fd;
  char *buffer;
  size_t buffer_size;
  size_t buffer_length;
  bool eof;
  volatile sig_atomic_t completed;
  int status;
  struct plugin *next;
} plugin;

static plugin *plugin_list = NULL;

/* Gets an existing plugin based on name,
   or if none is found, creates a new one */
__attribute__((warn_unused_result))
static plugin *getplugin(char *name){
  /* Check for existing plugin with that name */
  for(plugin *p = plugin_list; p != NULL; p = p->next){
    if((p->name == name)
       or (p->name and name and (strcmp(p->name, name) == 0))){
      return p;
    }
  }
  /* Create a new plugin */
  plugin *new_plugin = NULL;
  do {
    new_plugin = malloc(sizeof(plugin));
  } while(new_plugin == NULL and errno == EINTR);
  if(new_plugin == NULL){
    return NULL;
  }
  char *copy_name = NULL;
  if(name != NULL){
    do {
      copy_name = strdup(name);
    } while(copy_name == NULL and errno == EINTR);
    if(copy_name == NULL){
      int e = errno;
      free(new_plugin);
      errno = e;
      return NULL;
    }
  }
  
  *new_plugin = (plugin){ .name = copy_name,
			  .argc = 1,
			  .disabled = false,
			  .next = plugin_list };
  
  do {
    new_plugin->argv = malloc(sizeof(char *) * 2);
  } while(new_plugin->argv == NULL and errno == EINTR);
  if(new_plugin->argv == NULL){
    int e = errno;
    free(copy_name);
    free(new_plugin);
    errno = e;
    return NULL;
  }
  new_plugin->argv[0] = copy_name;
  new_plugin->argv[1] = NULL;
  
  do {
    new_plugin->environ = malloc(sizeof(char *));
  } while(new_plugin->environ == NULL and errno == EINTR);
  if(new_plugin->environ == NULL){
    int e = errno;
    free(copy_name);
    free(new_plugin->argv);
    free(new_plugin);
    errno = e;
    return NULL;
  }
  new_plugin->environ[0] = NULL;
  
  /* Append the new plugin to the list */
  plugin_list = new_plugin;
  return new_plugin;
}

/* Helper function for add_argument and add_environment */
__attribute__((nonnull, warn_unused_result))
static bool add_to_char_array(const char *new, char ***array,
			      int *len){
  /* Resize the pointed-to array to hold one more pointer */
  char **new_array = NULL;
  do {
    new_array = realloc(*array, sizeof(char *)
			* (size_t) ((*len) + 2));
  } while(new_array == NULL and errno == EINTR);
  /* Malloc check */
  if(new_array == NULL){
    return false;
  }
  *array = new_array;
  /* Make a copy of the new string */
  char *copy;
  do {
    copy = strdup(new);
  } while(copy == NULL and errno == EINTR);
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
__attribute__((nonnull(2), warn_unused_result))
static bool add_argument(plugin *p, const char *arg){
  if(p == NULL){
    return false;
  }
  return add_to_char_array(arg, &(p->argv), &(p->argc));
}

/* Add to a plugin's environment */
__attribute__((nonnull(2), warn_unused_result))
static bool add_environment(plugin *p, const char *def, bool replace){
  if(p == NULL){
    return false;
  }
  /* namelen = length of name of environment variable */
  size_t namelen = (size_t)(strchrnul(def, '=') - def);
  /* Search for this environment variable */
  for(char **envdef = p->environ; *envdef != NULL; envdef++){
    if(strncmp(*envdef, def, namelen + 1) == 0){
      /* It already exists */
      if(replace){
	char *new_envdef;
	do {
	  new_envdef = realloc(*envdef, strlen(def) + 1);
	} while(new_envdef == NULL and errno == EINTR);
	if(new_envdef == NULL){
	  return false;
	}
	*envdef = new_envdef;
	strcpy(*envdef, def);
      }
      return true;
    }
  }
  return add_to_char_array(def, &(p->environ), &(p->envc));
}

#ifndef O_CLOEXEC
/*
 * Based on the example in the GNU LibC manual chapter 13.13 "File
 * Descriptor Flags".
 | [[info:libc:Descriptor%20Flags][File Descriptor Flags]] |
 */
__attribute__((warn_unused_result))
static int set_cloexec_flag(int fd){
  int ret = (int)TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
  /* If reading the flags failed, return error indication now. */
  if(ret < 0){
    return ret;
  }
  /* Store modified flag word in the descriptor. */
  return (int)TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD,
				       ret | FD_CLOEXEC));
}
#endif	/* not O_CLOEXEC */


/* Mark processes as completed when they exit, and save their exit
   status. */
static void handle_sigchld(__attribute__((unused)) int sig){
  int old_errno = errno;
  while(true){
    plugin *proc = plugin_list;
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if(pid == 0){
      /* Only still running child processes */
      break;
    }
    if(pid == -1){
      if(errno == ECHILD){
	/* No child processes */
	break;
      }
      error(0, errno, "waitpid");
    }
    
    /* A child exited, find it in process_list */
    while(proc != NULL and proc->pid != pid){
      proc = proc->next;
    }
    if(proc == NULL){
      /* Process not found in process list */
      continue;
    }
    proc->status = status;
    proc->completed = 1;
  }
  errno = old_errno;
}

/* Prints out a password to stdout */
__attribute__((nonnull, warn_unused_result))
static bool print_out_password(const char *buffer, size_t length){
  ssize_t ret;
  for(size_t written = 0; written < length; written += (size_t)ret){
    ret = TEMP_FAILURE_RETRY(write(STDOUT_FILENO, buffer + written,
				   length - written));
    if(ret < 0){
      return false;
    }
  }
  return true;
}

/* Removes and free a plugin from the plugin list */
__attribute__((nonnull))
static void free_plugin(plugin *plugin_node){
  
  for(char **arg = plugin_node->argv; *arg != NULL; arg++){
    free(*arg);
  }
  free(plugin_node->argv);
  for(char **env = plugin_node->environ; *env != NULL; env++){
    free(*env);
  }
  free(plugin_node->environ);
  free(plugin_node->buffer);
  
  /* Removes the plugin from the singly-linked list */
  if(plugin_node == plugin_list){
    /* First one - simple */
    plugin_list = plugin_list->next;
  } else {
    /* Second one or later */
    for(plugin *p = plugin_list; p != NULL; p = p->next){
      if(p->next == plugin_node){
	p->next = plugin_node->next;
	break;
      }
    }
  }
  
  free(plugin_node);
}

static void free_plugin_list(void){
  while(plugin_list != NULL){
    free_plugin(plugin_list);
  }
}

int main(int argc, char *argv[]){
  char *plugindir = NULL;
  char *pluginhelperdir = NULL;
  char *argfile = NULL;
  FILE *conffp;
  struct dirent **direntries = NULL;
  struct stat st;
  fd_set rfds_all;
  int ret, maxfd = 0;
  ssize_t sret;
  uid_t uid = 65534;
  gid_t gid = 65534;
  bool debug = false;
  int exitstatus = EXIT_SUCCESS;
  struct sigaction old_sigchld_action;
  struct sigaction sigchld_action = { .sa_handler = handle_sigchld,
				      .sa_flags = SA_NOCLDSTOP };
  char **custom_argv = NULL;
  int custom_argc = 0;
  int dir_fd = -1;
  
  /* Establish a signal handler */
  sigemptyset(&sigchld_action.sa_mask);
  ret = sigaddset(&sigchld_action.sa_mask, SIGCHLD);
  if(ret == -1){
    error(0, errno, "sigaddset");
    exitstatus = EX_OSERR;
    goto fallback;
  }
  ret = sigaction(SIGCHLD, &sigchld_action, &old_sigchld_action);
  if(ret == -1){
    error(0, errno, "sigaction");
    exitstatus = EX_OSERR;
    goto fallback;
  }
  
  /* The options we understand. */
  struct argp_option options[] = {
    { .name = "global-options", .key = 'g',
      .arg = "OPTION[,OPTION[,...]]",
      .doc = "Options passed to all plugins" },
    { .name = "global-env", .key = 'G',
      .arg = "VAR=value",
      .doc = "Environment variable passed to all plugins" },
    { .name = "options-for", .key = 'o',
      .arg = "PLUGIN:OPTION[,OPTION[,...]]",
      .doc = "Options passed only to specified plugin" },
    { .name = "env-for", .key = 'E',
      .arg = "PLUGIN:ENV=value",
      .doc = "Environment variable passed to specified plugin" },
    { .name = "disable", .key = 'd',
      .arg = "PLUGIN",
      .doc = "Disable a specific plugin", .group = 1 },
    { .name = "enable", .key = 'e',
      .arg = "PLUGIN",
      .doc = "Enable a specific plugin", .group = 1 },
    { .name = "plugin-dir", .key = 128,
      .arg = "DIRECTORY",
      .doc = "Specify a different plugin directory", .group = 2 },
    { .name = "config-file", .key = 129,
      .arg = "FILE",
      .doc = "Specify a different configuration file", .group = 2 },
    { .name = "userid", .key = 130,
      .arg = "ID", .flags = 0,
      .doc = "User ID the plugins will run as", .group = 3 },
    { .name = "groupid", .key = 131,
      .arg = "ID", .flags = 0,
      .doc = "Group ID the plugins will run as", .group = 3 },
    { .name = "debug", .key = 132,
      .doc = "Debug mode", .group = 4 },
    { .name = "plugin-helper-dir", .key = 133,
      .arg = "DIRECTORY",
      .doc = "Specify a different plugin helper directory",
      .group = 2 },
    /*
     * These reproduce what we would get without ARGP_NO_HELP
     */
    { .name = "help", .key = '?',
      .doc = "Give this help list", .group = -1 },
    { .name = "usage", .key = -3,
      .doc = "Give a short usage message", .group = -1 },
    { .name = "version", .key = 'V',
      .doc = "Print program version", .group = -1 },
    { .name = NULL }
  };
  
  __attribute__((nonnull(3)))
  error_t parse_opt(int key, char *arg, struct argp_state *state){
    errno = 0;
    switch(key){
      char *tmp;
      intmax_t tmp_id;
    case 'g': 			/* --global-options */
      {
	char *plugin_option;
	while((plugin_option = strsep(&arg, ",")) != NULL){
	  if(not add_argument(getplugin(NULL), plugin_option)){
	    break;
	  }
	}
	errno = 0;
      }
      break;
    case 'G':			/* --global-env */
      if(add_environment(getplugin(NULL), arg, true)){
	errno = 0;
      }
      break;
    case 'o':			/* --options-for */
      {
	char *option_list = strchr(arg, ':');
	if(option_list == NULL){
	  argp_error(state, "No colon in \"%s\"", arg);
	  errno = EINVAL;
	  break;
	}
	*option_list = '\0';
	option_list++;
	if(arg[0] == '\0'){
	  argp_error(state, "Empty plugin name");
	  errno = EINVAL;
	  break;
	}
	char *option;
	while((option = strsep(&option_list, ",")) != NULL){
	  if(not add_argument(getplugin(arg), option)){
	    break;
	  }
	}
	errno = 0;
      }
      break;
    case 'E':			/* --env-for */
      {
	char *envdef = strchr(arg, ':');
	if(envdef == NULL){
	  argp_error(state, "No colon in \"%s\"", arg);
	  errno = EINVAL;
	  break;
	}
	*envdef = '\0';
	envdef++;
	if(arg[0] == '\0'){
	  argp_error(state, "Empty plugin name");
	  errno = EINVAL;
	  break;
	}
	if(add_environment(getplugin(arg), envdef, true)){
	  errno = 0;
	}
      }
      break;
    case 'd':			/* --disable */
      {
	plugin *p = getplugin(arg);
	if(p != NULL){
	  p->disabled = true;
	  errno = 0;
	}
      }
      break;
    case 'e':			/* --enable */
      {
	plugin *p = getplugin(arg);
	if(p != NULL){
	  p->disabled = false;
	  errno = 0;
	}
      }
      break;
    case 128:			/* --plugin-dir */
      free(plugindir);
      plugindir = strdup(arg);
      if(plugindir != NULL){
	errno = 0;
      }
      break;
    case 129:			/* --config-file */
      /* This is already done by parse_opt_config_file() */
      break;
    case 130:			/* --userid */
      tmp_id = strtoimax(arg, &tmp, 10);
      if(errno != 0 or tmp == arg or *tmp != '\0'
	 or tmp_id != (uid_t)tmp_id){
	argp_error(state, "Bad user ID number: \"%s\", using %"
		   PRIdMAX, arg, (intmax_t)uid);
	break;
      }
      uid = (uid_t)tmp_id;
      errno = 0;
      break;
    case 131:			/* --groupid */
      tmp_id = strtoimax(arg, &tmp, 10);
      if(errno != 0 or tmp == arg or *tmp != '\0'
	 or tmp_id != (gid_t)tmp_id){
	argp_error(state, "Bad group ID number: \"%s\", using %"
		   PRIdMAX, arg, (intmax_t)gid);
	break;
      }
      gid = (gid_t)tmp_id;
      errno = 0;
      break;
    case 132:			/* --debug */
      debug = true;
      break;
    case 133:			/* --plugin-helper-dir */
      free(pluginhelperdir);
      pluginhelperdir = strdup(arg);
      if(pluginhelperdir != NULL){
	errno = 0;
      }
      break;
      /*
       * These reproduce what we would get without ARGP_NO_HELP
       */
    case '?':			/* --help */
      state->flags &= ~(unsigned int)ARGP_NO_EXIT; /* force exit */
      argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
    case -3:			/* --usage */
      state->flags &= ~(unsigned int)ARGP_NO_EXIT; /* force exit */
      argp_state_help(state, state->out_stream,
		      ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
    case 'V':			/* --version */
      fprintf(state->out_stream, "%s\n", argp_program_version);
      exit(EXIT_SUCCESS);
      break;
/*
 * When adding more options before this line, remember to also add a
 * "case" to the "parse_opt_config_file" function below.
 */
    case ARGP_KEY_ARG:
      /* Cryptsetup always passes an argument, which is an empty
	 string if "none" was specified in /etc/crypttab.  So if
	 argument was empty, we ignore it silently. */
      if(arg[0] == '\0'){
	break;
      }
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return errno;		/* Set to 0 at start */
  }
  
  /* This option parser is the same as parse_opt() above, except it
     ignores everything but the --config-file option. */
  error_t parse_opt_config_file(int key, char *arg,
				__attribute__((unused))
				struct argp_state *state){
    errno = 0;
    switch(key){
    case 'g': 			/* --global-options */
    case 'G':			/* --global-env */
    case 'o':			/* --options-for */
    case 'E':			/* --env-for */
    case 'd':			/* --disable */
    case 'e':			/* --enable */
    case 128:			/* --plugin-dir */
      break;
    case 129:			/* --config-file */
      free(argfile);
      argfile = strdup(arg);
      if(argfile != NULL){
	errno = 0;
      }
      break;
    case 130:			/* --userid */
    case 131:			/* --groupid */
    case 132:			/* --debug */
    case 133:			/* --plugin-helper-dir */
    case '?':			/* --help */
    case -3:			/* --usage */
    case 'V':			/* --version */
    case ARGP_KEY_ARG:
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return errno;
  }
  
  struct argp argp = { .options = options,
		       .parser = parse_opt_config_file,
		       .args_doc = "",
		       .doc = "Mandos plugin runner -- Run plugins" };
  
  /* Parse using parse_opt_config_file() in order to get the custom
     config file location, if any. */
  ret = argp_parse(&argp, argc, argv,
		   ARGP_IN_ORDER | ARGP_NO_EXIT | ARGP_NO_HELP,
		   NULL, NULL);
  switch(ret){
  case 0:
    break;
  case ENOMEM:
  default:
    errno = ret;
    error(0, errno, "argp_parse");
    exitstatus = EX_OSERR;
    goto fallback;
  case EINVAL:
    exitstatus = EX_USAGE;
    goto fallback;
  }
  
  /* Reset to the normal argument parser */
  argp.parser = parse_opt;
  
  /* Open the configfile if available */
  if(argfile == NULL){
    conffp = fopen(AFILE, "r");
  } else {
    conffp = fopen(argfile, "r");
  }
  if(conffp != NULL){
    char *org_line = NULL;
    char *p, *arg, *new_arg, *line;
    size_t size = 0;
    const char whitespace_delims[] = " \r\t\f\v\n";
    const char comment_delim[] = "#";
    
    custom_argc = 1;
    custom_argv = malloc(sizeof(char*) * 2);
    if(custom_argv == NULL){
      error(0, errno, "malloc");
      exitstatus = EX_OSERR;
      goto fallback;
    }
    custom_argv[0] = argv[0];
    custom_argv[1] = NULL;
    
    /* for each line in the config file, strip whitespace and ignore
       commented text */
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
	if(new_arg == NULL){
	  error(0, errno, "strdup");
	  exitstatus = EX_OSERR;
	  free(org_line);
	  goto fallback;
	}
	
	custom_argc += 1;
	{
	  char **new_argv = realloc(custom_argv, sizeof(char *)
				    * ((size_t)custom_argc + 1));
	  if(new_argv == NULL){
	    error(0, errno, "realloc");
	    exitstatus = EX_OSERR;
	    free(new_arg);
	    free(org_line);
	    goto fallback;
	  } else {
	    custom_argv = new_argv;
	  }
	}
	custom_argv[custom_argc-1] = new_arg;
	custom_argv[custom_argc] = NULL;
      }
    }
    do {
      ret = fclose(conffp);
    } while(ret == EOF and errno == EINTR);
    if(ret == EOF){
      error(0, errno, "fclose");
      exitstatus = EX_IOERR;
      goto fallback;
    }
    free(org_line);
  } else {
    /* Check for harmful errors and go to fallback. Other errors might
       not affect opening plugins */
    if(errno == EMFILE or errno == ENFILE or errno == ENOMEM){
      error(0, errno, "fopen");
      exitstatus = EX_OSERR;
      goto fallback;
    }
  }
  /* If there were any arguments from the configuration file, pass
     them to parser as command line arguments */
  if(custom_argv != NULL){
    ret = argp_parse(&argp, custom_argc, custom_argv,
		     ARGP_IN_ORDER | ARGP_NO_EXIT | ARGP_NO_HELP,
		     NULL, NULL);
    switch(ret){
    case 0:
      break;
    case ENOMEM:
    default:
      errno = ret;
      error(0, errno, "argp_parse");
      exitstatus = EX_OSERR;
      goto fallback;
    case EINVAL:
      exitstatus = EX_CONFIG;
      goto fallback;
    }
  }
  
  /* Parse actual command line arguments, to let them override the
     config file */
  ret = argp_parse(&argp, argc, argv,
		   ARGP_IN_ORDER | ARGP_NO_EXIT | ARGP_NO_HELP,
		   NULL, NULL);
  switch(ret){
  case 0:
    break;
  case ENOMEM:
  default:
    errno = ret;
    error(0, errno, "argp_parse");
    exitstatus = EX_OSERR;
    goto fallback;
  case EINVAL:
    exitstatus = EX_USAGE;
    goto fallback;
  }
  
  {
    char *pluginhelperenv;
    bool bret = true;
    ret = asprintf(&pluginhelperenv, "MANDOSPLUGINHELPERDIR=%s",
		   pluginhelperdir != NULL ? pluginhelperdir : PHDIR);
    if(ret != -1){
      bret = add_environment(getplugin(NULL), pluginhelperenv, true);
    }
    if(ret == -1 or not bret){
      error(0, errno, "Failed to set MANDOSPLUGINHELPERDIR"
	    " environment variable to \"%s\" for all plugins\n",
	    pluginhelperdir != NULL ? pluginhelperdir : PHDIR);
    }
    if(ret != -1){
      free(pluginhelperenv);
    }
  }
  
  if(debug){
    for(plugin *p = plugin_list; p != NULL; p = p->next){
      fprintf(stderr, "Plugin: %s has %d arguments\n",
	      p->name ? p->name : "Global", p->argc - 1);
      for(char **a = p->argv; *a != NULL; a++){
	fprintf(stderr, "\tArg: %s\n", *a);
      }
      fprintf(stderr, "...and %d environment variables\n", p->envc);
      for(char **a = p->environ; *a != NULL; a++){
	fprintf(stderr, "\t%s\n", *a);
      }
    }
  }
  
  if(getuid() == 0){
    /* Work around Debian bug #633582:
       <https://bugs.debian.org/633582> */
    int plugindir_fd = open(/* plugindir or */ PDIR, O_RDONLY);
    if(plugindir_fd == -1){
      if(errno != ENOENT){
	error(0, errno, "open(\"" PDIR "\")");
      }
    } else {
      ret = (int)TEMP_FAILURE_RETRY(fstat(plugindir_fd, &st));
      if(ret == -1){
	error(0, errno, "fstat");
      } else {
	if(S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0){
	  ret = fchown(plugindir_fd, uid, gid);
	  if(ret == -1){
	    error(0, errno, "fchown");
	  }
	}
      }
      close(plugindir_fd);
    }
  }
  
  /* Lower permissions */
  ret = setgid(gid);
  if(ret == -1){
    error(0, errno, "setgid");
  }
  ret = setuid(uid);
  if(ret == -1){
    error(0, errno, "setuid");
  }
  
  /* Open plugin directory with close_on_exec flag */
  {
    dir_fd = open(plugindir != NULL ? plugindir : PDIR, O_RDONLY |
#ifdef O_CLOEXEC
		  O_CLOEXEC
#else  /* not O_CLOEXEC */
		  0
#endif	/* not O_CLOEXEC */
		  );
    if(dir_fd == -1){
      error(0, errno, "Could not open plugin dir");
      exitstatus = EX_UNAVAILABLE;
      goto fallback;
    }
    
#ifndef O_CLOEXEC
  /* Set the FD_CLOEXEC flag on the directory */
    ret = set_cloexec_flag(dir_fd);
    if(ret < 0){
      error(0, errno, "set_cloexec_flag");
      exitstatus = EX_OSERR;
      goto fallback;
    }
#endif	/* O_CLOEXEC */
  }
  
  int good_name(const struct dirent * const dirent){
    const char * const patterns[] = { ".*", "#*#", "*~", "*.dpkg-new",
				      "*.dpkg-old", "*.dpkg-bak",
				      "*.dpkg-divert", NULL };
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    for(const char **pat = (const char **)patterns;
	*pat != NULL; pat++){
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
      if(fnmatch(*pat, dirent->d_name, FNM_FILE_NAME | FNM_PERIOD)
	 != FNM_NOMATCH){
	if(debug){
	    fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		    " matching pattern %s\n", dirent->d_name, *pat);
	}
	return 0;
      }
    }
    return 1;
  }
  
  int numplugins = scandirat(dir_fd, ".", &direntries, good_name,
			     alphasort);
  if(numplugins == -1){
    error(0, errno, "Could not scan plugin dir");
    direntries = NULL;
    exitstatus = EX_OSERR;
    goto fallback;
  }
  
  FD_ZERO(&rfds_all);
  
  /* Read and execute any executable in the plugin directory*/
  for(int i = 0; i < numplugins; i++){
    
    int plugin_fd = openat(dir_fd, direntries[i]->d_name, O_RDONLY);
    if(plugin_fd == -1){
      error(0, errno, "Could not open plugin");
      free(direntries[i]);
      continue;
    }
    ret = (int)TEMP_FAILURE_RETRY(fstat(plugin_fd, &st));
    if(ret == -1){
      error(0, errno, "stat");
      close(plugin_fd);
      free(direntries[i]);
      continue;
    }
    
    /* Ignore non-executable files */
    if(not S_ISREG(st.st_mode)
       or (TEMP_FAILURE_RETRY(faccessat(dir_fd, direntries[i]->d_name,
					X_OK, 0)) != 0)){
      if(debug){
	fprintf(stderr, "Ignoring plugin dir entry \"%s/%s\""
		" with bad type or mode\n",
		plugindir != NULL ? plugindir : PDIR,
		direntries[i]->d_name);
      }
      close(plugin_fd);
      free(direntries[i]);
      continue;
    }
    
    plugin *p = getplugin(direntries[i]->d_name);
    if(p == NULL){
      error(0, errno, "getplugin");
      close(plugin_fd);
      free(direntries[i]);
      continue;
    }
    if(p->disabled){
      if(debug){
	fprintf(stderr, "Ignoring disabled plugin \"%s\"\n",
		direntries[i]->d_name);
      }
      close(plugin_fd);
      free(direntries[i]);
      continue;
    }
    {
      /* Add global arguments to argument list for this plugin */
      plugin *g = getplugin(NULL);
      if(g != NULL){
	for(char **a = g->argv + 1; *a != NULL; a++){
	  if(not add_argument(p, *a)){
	    error(0, errno, "add_argument");
	  }
	}
	/* Add global environment variables */
	for(char **e = g->environ; *e != NULL; e++){
	  if(not add_environment(p, *e, false)){
	    error(0, errno, "add_environment");
	  }
	}
      }
    }
    /* If this plugin has any environment variables, we need to
       duplicate the environment from this process, too. */
    if(p->environ[0] != NULL){
      for(char **e = environ; *e != NULL; e++){
	if(not add_environment(p, *e, false)){
	  error(0, errno, "add_environment");
	}
      }
    }
    
    int pipefd[2];
#ifndef O_CLOEXEC
    ret = (int)TEMP_FAILURE_RETRY(pipe(pipefd));
#else  /* O_CLOEXEC */
    ret = (int)TEMP_FAILURE_RETRY(pipe2(pipefd, O_CLOEXEC));
#endif	/* O_CLOEXEC */
    if(ret == -1){
      error(0, errno, "pipe");
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
    if(pipefd[0] >= FD_SETSIZE){
      fprintf(stderr, "pipe()[0] (%d) >= FD_SETSIZE (%d)", pipefd[0],
	      FD_SETSIZE);
      close(pipefd[0]);
      close(pipefd[1]);
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
#ifndef O_CLOEXEC
    /* Ask OS to automatic close the pipe on exec */
    ret = set_cloexec_flag(pipefd[0]);
    if(ret < 0){
      error(0, errno, "set_cloexec_flag");
      close(pipefd[0]);
      close(pipefd[1]);
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
    ret = set_cloexec_flag(pipefd[1]);
    if(ret < 0){
      error(0, errno, "set_cloexec_flag");
      close(pipefd[0]);
      close(pipefd[1]);
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
#endif	/* not O_CLOEXEC */
    /* Block SIGCHLD until process is safely in process list */
    ret = (int)TEMP_FAILURE_RETRY(sigprocmask(SIG_BLOCK,
					      &sigchld_action.sa_mask,
					      NULL));
    if(ret < 0){
      error(0, errno, "sigprocmask");
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
    /* Starting a new process to be watched */
    pid_t pid;
    do {
      pid = fork();
    } while(pid == -1 and errno == EINTR);
    if(pid == -1){
      error(0, errno, "fork");
      TEMP_FAILURE_RETRY(sigprocmask(SIG_UNBLOCK,
				     &sigchld_action.sa_mask, NULL));
      close(pipefd[0]);
      close(pipefd[1]);
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
    if(pid == 0){
      /* this is the child process */
      ret = sigaction(SIGCHLD, &old_sigchld_action, NULL);
      if(ret < 0){
	error(0, errno, "sigaction");
	_exit(EX_OSERR);
      }
      ret = sigprocmask(SIG_UNBLOCK, &sigchld_action.sa_mask, NULL);
      if(ret < 0){
	error(0, errno, "sigprocmask");
	_exit(EX_OSERR);
      }
      
      ret = dup2(pipefd[1], STDOUT_FILENO); /* replace our stdout */
      if(ret == -1){
	error(0, errno, "dup2");
	_exit(EX_OSERR);
      }
      
      if(fexecve(plugin_fd, p->argv,
		(p->environ[0] != NULL) ? p->environ : environ) < 0){
	error(0, errno, "fexecve for %s/%s",
	      plugindir != NULL ? plugindir : PDIR,
	      direntries[i]->d_name);
	_exit(EX_OSERR);
      }
      /* no return */
    }
    /* Parent process */
    close(pipefd[1]);		/* Close unused write end of pipe */
    close(plugin_fd);
    plugin *new_plugin = getplugin(direntries[i]->d_name);
    if(new_plugin == NULL){
      error(0, errno, "getplugin");
      ret = (int)(TEMP_FAILURE_RETRY
		  (sigprocmask(SIG_UNBLOCK, &sigchld_action.sa_mask,
			       NULL)));
      if(ret < 0){
        error(0, errno, "sigprocmask");
      }
      exitstatus = EX_OSERR;
      free(direntries[i]);
      goto fallback;
    }
    free(direntries[i]);
    
    new_plugin->pid = pid;
    new_plugin->fd = pipefd[0];
    
    /* Unblock SIGCHLD so signal handler can be run if this process
       has already completed */
    ret = (int)TEMP_FAILURE_RETRY(sigprocmask(SIG_UNBLOCK,
					      &sigchld_action.sa_mask,
					      NULL));
    if(ret < 0){
      error(0, errno, "sigprocmask");
      exitstatus = EX_OSERR;
      goto fallback;
    }
    
    FD_SET(new_plugin->fd, &rfds_all);
    
    if(maxfd < new_plugin->fd){
      maxfd = new_plugin->fd;
    }
  }
  
  free(direntries);
  direntries = NULL;
  close(dir_fd);
  dir_fd = -1;
  free_plugin(getplugin(NULL));
  
  for(plugin *p = plugin_list; p != NULL; p = p->next){
    if(p->pid != 0){
      break;
    }
    if(p->next == NULL){
      fprintf(stderr, "No plugin processes started. Incorrect plugin"
	      " directory?\n");
      free_plugin_list();
    }
  }
  
  /* Main loop while running plugins exist */
  while(plugin_list){
    fd_set rfds = rfds_all;
    int select_ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
    if(select_ret == -1 and errno != EINTR){
      error(0, errno, "select");
      exitstatus = EX_OSERR;
      goto fallback;
    }
    /* OK, now either a process completed, or something can be read
       from one of them */
    for(plugin *proc = plugin_list; proc != NULL;){
      /* Is this process completely done? */
      if(proc->completed and proc->eof){
	/* Only accept the plugin output if it exited cleanly */
	if(not WIFEXITED(proc->status)
	   or WEXITSTATUS(proc->status) != 0){
	  /* Bad exit by plugin */
	  
	  if(debug){
	    if(WIFEXITED(proc->status)){
	      fprintf(stderr, "Plugin %s [%" PRIdMAX "] exited with"
		      " status %d\n", proc->name,
		      (intmax_t) (proc->pid),
		      WEXITSTATUS(proc->status));
	    } else if(WIFSIGNALED(proc->status)){
	      fprintf(stderr, "Plugin %s [%" PRIdMAX "] killed by"
		      " signal %d: %s\n", proc->name,
		      (intmax_t) (proc->pid),
		      WTERMSIG(proc->status),
		      strsignal(WTERMSIG(proc->status)));
	    }
	  }
	  
	  /* Remove the plugin */
	  FD_CLR(proc->fd, &rfds_all);
	  
	  /* Block signal while modifying process_list */
	  ret = (int)TEMP_FAILURE_RETRY(sigprocmask
					(SIG_BLOCK,
					 &sigchld_action.sa_mask,
					 NULL));
	  if(ret < 0){
	    error(0, errno, "sigprocmask");
	    exitstatus = EX_OSERR;
	    goto fallback;
	  }
	  
	  plugin *next_plugin = proc->next;
	  free_plugin(proc);
	  proc = next_plugin;
	  
	  /* We are done modifying process list, so unblock signal */
	  ret = (int)(TEMP_FAILURE_RETRY
		      (sigprocmask(SIG_UNBLOCK,
				   &sigchld_action.sa_mask, NULL)));
	  if(ret < 0){
	    error(0, errno, "sigprocmask");
	    exitstatus = EX_OSERR;
	    goto fallback;
	  }
	  
	  if(plugin_list == NULL){
	    break;
	  }
	  
	  continue;
	}
	
	/* This process exited nicely, so print its buffer */
	
	bool bret = print_out_password(proc->buffer,
				       proc->buffer_length);
	if(not bret){
	  error(0, errno, "print_out_password");
	  exitstatus = EX_IOERR;
	}
	goto fallback;
      }
      
      /* This process has not completed.  Does it have any output? */
      if(proc->eof or not FD_ISSET(proc->fd, &rfds)){
	/* This process had nothing to say at this time */
	proc = proc->next;
	continue;
      }
      /* Before reading, make the process' data buffer large enough */
      if(proc->buffer_length + BUFFER_SIZE > proc->buffer_size){
	char *new_buffer = realloc(proc->buffer, proc->buffer_size
				   + (size_t) BUFFER_SIZE);
	if(new_buffer == NULL){
	  error(0, errno, "malloc");
	  exitstatus = EX_OSERR;
	  goto fallback;
	}
	proc->buffer = new_buffer;
	proc->buffer_size += BUFFER_SIZE;
      }
      /* Read from the process */
      sret = TEMP_FAILURE_RETRY(read(proc->fd,
				     proc->buffer
				     + proc->buffer_length,
				     BUFFER_SIZE));
      if(sret < 0){
	/* Read error from this process; ignore the error */
	proc = proc->next;
	continue;
      }
      if(sret == 0){
	/* got EOF */
	proc->eof = true;
      } else {
	proc->buffer_length += (size_t) sret;
      }
    }
  }
  
  
 fallback:
  
  if(plugin_list == NULL or (exitstatus != EXIT_SUCCESS
			     and exitstatus != EX_OK)){
    /* Fallback if all plugins failed, none are found or an error
       occured */
    bool bret;
    fprintf(stderr, "Going to fallback mode using getpass(3)\n");
    char *passwordbuffer = getpass("Password: ");
    size_t len = strlen(passwordbuffer);
    /* Strip trailing newline */
    if(len > 0 and passwordbuffer[len-1] == '\n'){
      passwordbuffer[len-1] = '\0'; /* not strictly necessary */
      len--;
    }
    bret = print_out_password(passwordbuffer, len);
    if(not bret){
      error(0, errno, "print_out_password");
      exitstatus = EX_IOERR;
    }
  }
  
  /* Restore old signal handler */
  ret = sigaction(SIGCHLD, &old_sigchld_action, NULL);
  if(ret == -1){
    error(0, errno, "sigaction");
    exitstatus = EX_OSERR;
  }
  
  if(custom_argv != NULL){
    for(char **arg = custom_argv+1; *arg != NULL; arg++){
      free(*arg);
    }
    free(custom_argv);
  }
  
  free(direntries);
  
  if(dir_fd != -1){
    close(dir_fd);
  }
  
  /* Kill the processes */
  for(plugin *p = plugin_list; p != NULL; p = p->next){
    if(p->pid != 0){
      close(p->fd);
      ret = kill(p->pid, SIGTERM);
      if(ret == -1 and errno != ESRCH){
	/* Set-uid proccesses might not get closed */
	error(0, errno, "kill");
      }
    }
  }
  
  /* Wait for any remaining child processes to terminate */
  do {
    ret = wait(NULL);
  } while(ret >= 0);
  if(errno != ECHILD){
    error(0, errno, "wait");
  }
  
  free_plugin_list();
  
  free(plugindir);
  free(pluginhelperdir);
  free(argfile);
  
  return exitstatus;
}
