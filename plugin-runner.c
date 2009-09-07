/*  -*- coding: utf-8; mode: c; mode: orgtbl -*- */
/*
 * Mandos plugin runner - Run Mandos plugins
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

#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY(), getline(),
				   asprintf() */
#include <stddef.h>		/* size_t, NULL */
#include <stdlib.h>		/* malloc(), exit(), EXIT_FAILURE,
				   EXIT_SUCCESS, realloc() */
#include <stdbool.h>		/* bool, true, false */
#include <stdio.h>		/* perror, fileno(), fprintf(),
				   stderr, STDOUT_FILENO */
#include <sys/types.h>	        /* DIR, opendir(), stat(), struct
				   stat, waitpid(), WIFEXITED(),
				   WEXITSTATUS(), wait(), pid_t,
				   uid_t, gid_t, getuid(), getgid(),
				   dirfd() */
#include <sys/select.h>		/* fd_set, select(), FD_ZERO(),
				   FD_SET(), FD_ISSET(), FD_CLR */
#include <sys/wait.h>		/* wait(), waitpid(), WIFEXITED(),
				   WEXITSTATUS(), WTERMSIG(),
				   WCOREDUMP() */
#include <sys/stat.h>		/* struct stat, stat(), S_ISREG() */
#include <iso646.h>		/* and, or, not */
#include <dirent.h>		/* DIR, struct dirent, opendir(),
				   readdir(), closedir(), dirfd() */
#include <unistd.h>		/* struct stat, stat(), S_ISREG(),
				   fcntl(), setuid(), setgid(),
				   F_GETFD, F_SETFD, FD_CLOEXEC,
				   access(), pipe(), fork(), close()
				   dup2(), STDOUT_FILENO, _exit(),
				   execv(), write(), read(),
				   close() */
#include <fcntl.h>		/* fcntl(), F_GETFD, F_SETFD,
				   FD_CLOEXEC */
#include <string.h>		/* strsep, strlen(), asprintf(),
				   strsignal() */
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

#define BUFFER_SIZE 256

#define PDIR "/lib/mandos/plugins.d"
#define AFILE "/conf/conf.d/mandos/plugin-runner.conf"

const char *argp_program_version = "plugin-runner " VERSION;
const char *argp_program_bug_address = "<mandos@fukt.bsnet.se>";

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
static plugin *getplugin(char *name){
  /* Check for exiting plugin with that name */
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
      free(new_plugin);
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
    free(copy_name);
    free(new_plugin);
    return NULL;
  }
  new_plugin->argv[0] = copy_name;
  new_plugin->argv[1] = NULL;
  
  do {
    new_plugin->environ = malloc(sizeof(char *));
  } while(new_plugin->environ == NULL and errno == EINTR);
  if(new_plugin->environ == NULL){
    free(copy_name);
    free(new_plugin->argv);
    free(new_plugin);
    return NULL;
  }
  new_plugin->environ[0] = NULL;
  
  /* Append the new plugin to the list */
  plugin_list = new_plugin;
  return new_plugin;
}

/* Helper function for add_argument and add_environment */
static bool add_to_char_array(const char *new, char ***array,
			      int *len){
  /* Resize the pointed-to array to hold one more pointer */
  do {
    *array = realloc(*array, sizeof(char *)
		     * (size_t) ((*len) + 2));
  } while(*array == NULL and errno == EINTR);
  /* Malloc check */
  if(*array == NULL){
    return false;
  }
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
static bool add_argument(plugin *p, const char *arg){
  if(p == NULL){
    return false;
  }
  return add_to_char_array(arg, &(p->argv), &(p->argc));
}

/* Add to a plugin's environment */
static bool add_environment(plugin *p, const char *def, bool replace){
  if(p == NULL){
    return false;
  }
  /* namelen = length of name of environment variable */
  size_t namelen = (size_t)(strchrnul(def, '=') - def);
  /* Search for this environment variable */
  for(char **e = p->environ; *e != NULL; e++){
    if(strncmp(*e, def, namelen + 1) == 0){
      /* It already exists */
      if(replace){
	char *new;
	do {
	  new = realloc(*e, strlen(def) + 1);
	} while(new == NULL and errno == EINTR);
	if(new == NULL){
	  return false;
	}
	*e = new;
	strcpy(*e, def);
      }
      return true;
    }
  }
  return add_to_char_array(def, &(p->environ), &(p->envc));
}

/*
 * Based on the example in the GNU LibC manual chapter 13.13 "File
 * Descriptor Flags".
 | [[info:libc:Descriptor%20Flags][File Descriptor Flags]] |
 */
static int set_cloexec_flag(int fd){
  int ret = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
  /* If reading the flags failed, return error indication now. */
  if(ret < 0){
    return ret;
  }
  /* Store modified flag word in the descriptor. */
  return TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, ret | FD_CLOEXEC));
}


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
      perror("waitpid");
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
  char *argfile = NULL;
  FILE *conffp;
  size_t d_name_len;
  DIR *dir = NULL;
  struct dirent *dirst;
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
    { .name = NULL }
  };
  
  error_t parse_opt(int key, char *arg, __attribute__((unused))
		    struct argp_state *state){
    switch(key){
      char *tmp;
      intmax_t tmpmax;
    case 'g': 			/* --global-options */
      if(arg != NULL){
	char *plugin_option;
	while((plugin_option = strsep(&arg, ",")) != NULL){
	  if(plugin_option[0] == '\0'){
	    continue;
	  }
	  if(not add_argument(getplugin(NULL), plugin_option)){
	    perror("add_argument");
	    return ARGP_ERR_UNKNOWN;
	  }
	}
      }
      break;
    case 'G':			/* --global-env */
      if(arg == NULL){
	break;
      }
      if(not add_environment(getplugin(NULL), arg, true)){
	perror("add_environment");
      }
      break;
    case 'o':			/* --options-for */
      if(arg != NULL){
	char *plugin_name = strsep(&arg, ":");
	if(plugin_name[0] == '\0'){
	  break;
	}
	char *plugin_option;
	while((plugin_option = strsep(&arg, ",")) != NULL){
	  if(not add_argument(getplugin(plugin_name), plugin_option)){
	    perror("add_argument");
	    return ARGP_ERR_UNKNOWN;
	  }
	}
      }
      break;
    case 'E':			/* --env-for */
      if(arg == NULL){
	break;
      }
      {
	char *envdef = strchr(arg, ':');
	if(envdef == NULL){
	  break;
	}
	*envdef = '\0';
	if(not add_environment(getplugin(arg), envdef+1, true)){
	  perror("add_environment");
	}
      }
      break;
    case 'd':			/* --disable */
      if(arg != NULL){
	plugin *p = getplugin(arg);
	if(p == NULL){
	  return ARGP_ERR_UNKNOWN;
	}
	p->disabled = true;
      }
      break;
    case 'e':			/* --enable */
      if(arg != NULL){
	plugin *p = getplugin(arg);
	if(p == NULL){
	  return ARGP_ERR_UNKNOWN;
	}
	p->disabled = false;
      }
      break;
    case 128:			/* --plugin-dir */
      free(plugindir);
      plugindir = strdup(arg);
      if(plugindir == NULL){
	perror("strdup");
      }
      break;
    case 129:			/* --config-file */
      /* This is already done by parse_opt_config_file() */
      break;
    case 130:			/* --userid */
      errno = 0;
      tmpmax = strtoimax(arg, &tmp, 10);
      if(errno != 0 or tmp == arg or *tmp != '\0'
	 or tmpmax != (uid_t)tmpmax){
	fprintf(stderr, "Bad user ID number: \"%s\", using %"
		PRIdMAX "\n", arg, (intmax_t)uid);
      } else {
	uid = (uid_t)tmpmax;
      }
      break;
    case 131:			/* --groupid */
      errno = 0;
      tmpmax = strtoimax(arg, &tmp, 10);
      if(errno != 0 or tmp == arg or *tmp != '\0'
	 or tmpmax != (gid_t)tmpmax){
	fprintf(stderr, "Bad group ID number: \"%s\", using %"
		PRIdMAX "\n", arg, (intmax_t)gid);
      } else {
	gid = (gid_t)tmpmax;
      }
      break;
    case 132:			/* --debug */
      debug = true;
      break;
/*
 * When adding more options before this line, remember to also add a
 * "case" to the "parse_opt_config_file" function below.
 */
    case ARGP_KEY_ARG:
      /* Cryptsetup always passes an argument, which is an empty
	 string if "none" was specified in /etc/crypttab.  So if
	 argument was empty, we ignore it silently. */
      if(arg[0] != '\0'){
	fprintf(stderr, "Ignoring unknown argument \"%s\"\n", arg);
      }
      break;
    case ARGP_KEY_END:
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return 0;
  }
  
  /* This option parser is the same as parse_opt() above, except it
     ignores everything but the --config-file option. */
  error_t parse_opt_config_file(int key, char *arg,
				__attribute__((unused))
				struct argp_state *state){
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
      if(argfile == NULL){
	perror("strdup");
      }
      break;
    case 130:			/* --userid */
    case 131:			/* --groupid */
    case 132:			/* --debug */
    case ARGP_KEY_ARG:
    case ARGP_KEY_END:
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return 0;
  }
  
  struct argp argp = { .options = options,
		       .parser = parse_opt_config_file,
		       .args_doc = "",
		       .doc = "Mandos plugin runner -- Run plugins" };
  
  /* Parse using parse_opt_config_file() in order to get the custom
     config file location, if any. */
  ret = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, NULL);
  if(ret == ARGP_ERR_UNKNOWN){
    fprintf(stderr, "Unknown error while parsing arguments\n");
    exitstatus = EXIT_FAILURE;
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
      perror("malloc");
      exitstatus = EXIT_FAILURE;
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
	  perror("strdup");
	  exitstatus = EXIT_FAILURE;
	  free(org_line);
	  goto fallback;
	}
	
	custom_argc += 1;
	custom_argv = realloc(custom_argv, sizeof(char *)
			      * ((unsigned int) custom_argc + 1));
	if(custom_argv == NULL){
	  perror("realloc");
	  exitstatus = EXIT_FAILURE;
	  free(org_line);
	  goto fallback;
	}
	custom_argv[custom_argc-1] = new_arg;
	custom_argv[custom_argc] = NULL;
      }
    }
    do {
      ret = fclose(conffp);
    } while(ret == EOF and errno == EINTR);
    if(ret == EOF){
      perror("fclose");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    free(org_line);
  } else {
    /* Check for harmful errors and go to fallback. Other errors might
       not affect opening plugins */
    if(errno == EMFILE or errno == ENFILE or errno == ENOMEM){
      perror("fopen");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
  }
  /* If there was any arguments from configuration file,
     pass them to parser as command arguments */
  if(custom_argv != NULL){
    ret = argp_parse(&argp, custom_argc, custom_argv, ARGP_IN_ORDER,
		     0, NULL);
    if(ret == ARGP_ERR_UNKNOWN){
      fprintf(stderr, "Unknown error while parsing arguments\n");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
  }
  
  /* Parse actual command line arguments, to let them override the
     config file */
  ret = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, NULL);
  if(ret == ARGP_ERR_UNKNOWN){
    fprintf(stderr, "Unknown error while parsing arguments\n");
    exitstatus = EXIT_FAILURE;
    goto fallback;
  }
  
  if(debug){
    for(plugin *p = plugin_list; p != NULL; p=p->next){
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
  
  /* Strip permissions down to nobody */
  setgid(gid);
  if(ret == -1){
    perror("setgid");
  }
  ret = setuid(uid);
  if(ret == -1){
    perror("setuid");
  }
  
  if(plugindir == NULL){
    dir = opendir(PDIR);
  } else {
    dir = opendir(plugindir);
  }
  
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
  
  /* Read and execute any executable in the plugin directory*/
  while(true){
    do {
      dirst = readdir(dir);
    } while(dirst == NULL and errno == EINTR);
    
    /* All directory entries have been processed */
    if(dirst == NULL){
      if(errno == EBADF){
	perror("readdir");
	exitstatus = EXIT_FAILURE;
	goto fallback;
      }
      break;
    }
    
    d_name_len = strlen(dirst->d_name);
    
    /* Ignore dotfiles, backup files and other junk */
    {
      bool bad_name = false;
      
      const char const *bad_prefixes[] = { ".", "#", NULL };
      
      const char const *bad_suffixes[] = { "~", "#", ".dpkg-new",
					   ".dpkg-old",
					   ".dpkg-bak",
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
    if(plugindir == NULL){
      ret = TEMP_FAILURE_RETRY(asprintf(&filename, PDIR "/%s",
					dirst->d_name));
    } else {
      ret = TEMP_FAILURE_RETRY(asprintf(&filename, "%s/%s", plugindir,
					dirst->d_name));
    }
    if(ret < 0){
      perror("asprintf");
      continue;
    }
    
    ret = TEMP_FAILURE_RETRY(stat(filename, &st));
    if(ret == -1){
      perror("stat");
      free(filename);
      continue;
    }
    
    /* Ignore non-executable files */
    if(not S_ISREG(st.st_mode)
       or (TEMP_FAILURE_RETRY(access(filename, X_OK)) != 0)){
      if(debug){
	fprintf(stderr, "Ignoring plugin dir entry \"%s\""
		" with bad type or mode\n", filename);
      }
      free(filename);
      continue;
    }
    
    plugin *p = getplugin(dirst->d_name);
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
      plugin *g = getplugin(NULL);
      if(g != NULL){
	for(char **a = g->argv + 1; *a != NULL; a++){
	  if(not add_argument(p, *a)){
	    perror("add_argument");
	  }
	}
	/* Add global environment variables */
	for(char **e = g->environ; *e != NULL; e++){
	  if(not add_environment(p, *e, false)){
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
	if(not add_environment(p, *e, false)){
	  perror("add_environment");
	}
      }
    }
    
    int pipefd[2];
    ret = TEMP_FAILURE_RETRY(pipe(pipefd));
    if(ret == -1){
      perror("pipe");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    /* Ask OS to automatic close the pipe on exec */
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
    ret = TEMP_FAILURE_RETRY(sigprocmask(SIG_BLOCK,
					 &sigchld_action.sa_mask,
					 NULL));
    if(ret < 0){
      perror("sigprocmask");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    /* Starting a new process to be watched */
    pid_t pid;
    do {
      pid = fork();
    } while(pid == -1 and errno == EINTR);
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
      ret = sigprocmask(SIG_UNBLOCK, &sigchld_action.sa_mask, NULL);
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
    /* Parent process */
    TEMP_FAILURE_RETRY(close(pipefd[1])); /* Close unused write end of
					     pipe */
    free(filename);
    plugin *new_plugin = getplugin(dirst->d_name);
    if(new_plugin == NULL){
      perror("getplugin");
      ret = TEMP_FAILURE_RETRY(sigprocmask(SIG_UNBLOCK,
					   &sigchld_action.sa_mask,
					   NULL));
      if(ret < 0){
        perror("sigprocmask");
      }
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    
    new_plugin->pid = pid;
    new_plugin->fd = pipefd[0];
    
    /* Unblock SIGCHLD so signal handler can be run if this process
       has already completed */
    ret = TEMP_FAILURE_RETRY(sigprocmask(SIG_UNBLOCK,
					 &sigchld_action.sa_mask,
					 NULL));
    if(ret < 0){
      perror("sigprocmask");
      exitstatus = EXIT_FAILURE;
      goto fallback;
    }
    
    FD_SET(new_plugin->fd, &rfds_all);
    
    if(maxfd < new_plugin->fd){
      maxfd = new_plugin->fd;
    }
  }
  
  TEMP_FAILURE_RETRY(closedir(dir));
  dir = NULL;
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
      perror("select");
      exitstatus = EXIT_FAILURE;
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
	    } else if(WCOREDUMP(proc->status)){
	      fprintf(stderr, "Plugin %s [%" PRIdMAX "] dumped"
		      " core\n", proc->name, (intmax_t) (proc->pid));
	    }
	  }
	  
	  /* Remove the plugin */
	  FD_CLR(proc->fd, &rfds_all);
	  
	  /* Block signal while modifying process_list */
	  ret = TEMP_FAILURE_RETRY(sigprocmask(SIG_BLOCK,
					       &sigchld_action.sa_mask,
					       NULL));
	  if(ret < 0){
	    perror("sigprocmask");
	    exitstatus = EXIT_FAILURE;
	    goto fallback;
	  }
	  
	  plugin *next_plugin = proc->next;
	  free_plugin(proc);
	  proc = next_plugin;
	  
	  /* We are done modifying process list, so unblock signal */
	  ret = TEMP_FAILURE_RETRY(sigprocmask(SIG_UNBLOCK,
					       &sigchld_action.sa_mask,
					       NULL));
	  if(ret < 0){
	    perror("sigprocmask");
	    exitstatus = EXIT_FAILURE;
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
	  perror("print_out_password");
	  exitstatus = EXIT_FAILURE;
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
	proc->buffer = realloc(proc->buffer, proc->buffer_size
			       + (size_t) BUFFER_SIZE);
	if(proc->buffer == NULL){
	  perror("malloc");
	  exitstatus = EXIT_FAILURE;
	  goto fallback;
	}
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
  
  if(plugin_list == NULL or exitstatus != EXIT_SUCCESS){
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
    for(char **arg = custom_argv+1; *arg != NULL; arg++){
      free(*arg);
    }
    free(custom_argv);
  }
  
  if(dir != NULL){
    closedir(dir);
  }
  
  /* Kill the processes */
  for(plugin *p = plugin_list; p != NULL; p = p->next){
    if(p->pid != 0){
      close(p->fd);
      ret = kill(p->pid, SIGTERM);
      if(ret == -1 and errno != ESRCH){
	/* Set-uid proccesses might not get closed */
	perror("kill");
      }
    }
  }
  
  /* Wait for any remaining child processes to terminate */
  do {
    ret = wait(NULL);
  } while(ret >= 0);
  if(errno != ECHILD){
    perror("wait");
  }
  
  free_plugin_list();
  
  free(plugindir);
  free(argfile);
  
  return exitstatus;
}
