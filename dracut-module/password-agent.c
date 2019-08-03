/* -*- mode: c; coding: utf-8; after-save-hook: (lambda () (let* ((find-build-directory (lambda (try-directory &optional base-directory) (let ((base-directory (or base-directory try-directory))) (cond ((equal try-directory "/") base-directory) ((file-readable-p (concat (file-name-as-directory try-directory) "Makefile")) try-directory) ((funcall find-build-directory (directory-file-name (file-name-directory try-directory)) base-directory)))))) (build-directory (funcall find-build-directory (buffer-file-name))) (local-build-directory (if (fboundp 'file-local-name) (file-local-name build-directory) (or (file-remote-p build-directory 'localname) build-directory))) (command (file-relative-name (file-name-sans-extension (buffer-file-name)) build-directory))) (pcase (progn (if (get-buffer "*Test*") (kill-buffer "*Test*")) (process-file-shell-command (let ((qbdir (shell-quote-argument local-build-directory)) (qcmd (shell-quote-argument command))) (format "cd %s && CFLAGS=-Werror make --silent %s && %s --test --verbose" qbdir qcmd qcmd)) nil "*Test*")) (0 (let ((w (get-buffer-window "*Test*"))) (if w (delete-window w)))) (_ (with-current-buffer "*Test*" (compilation-mode) (cd-absolute build-directory)) (display-buffer "*Test*" '(display-buffer-in-side-window)))))); -*- */
/*
 * Mandos password agent - Simple password agent to run Mandos client
 *
 * Copyright © 2019 Teddy Hogeborn
 * Copyright © 2019 Björn Påhlsson
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

#define _GNU_SOURCE
#include <inttypes.h>		/* uintmax_t, PRIuMAX, PRIdMAX,
				   intmax_t, uint32_t, SCNx32,
				   SCNuMAX, SCNxMAX */
#include <stddef.h>		/* size_t */
#include <sys/types.h>		/* pid_t, uid_t, gid_t, getuid(),
				   getpid() */
#include <stdbool.h>		/* bool, true, false */
#include <signal.h>		/* struct sigaction, sigset_t,
				   sigemptyset(), sigaddset(),
				   SIGCHLD, pthread_sigmask(),
				   SIG_BLOCK, SIG_SETMASK, SA_RESTART,
				   SA_NOCLDSTOP, sigfillset(), kill(),
				   SIGTERM, sigdelset(), SIGKILL,
				   NSIG, sigismember(), SA_ONSTACK,
				   SIG_DFL, SIG_IGN, SIGINT, SIGQUIT,
				   SIGHUP, SIGSTOP, SIG_UNBLOCK */
#include <stdlib.h>		/* EXIT_SUCCESS, EXIT_FAILURE,
				   malloc(), free(), strtoumax(),
				   realloc(), setenv(), calloc(),
				   mkdtemp(), mkostemp() */
#include <iso646.h>		/* not, or, and, xor */
#include <error.h>		/* error() */
#include <sysexits.h>		/* EX_USAGE, EX_OSERR, EX_OSFILE */
#include <errno.h>		/* errno, error_t, EACCES,
				   ENAMETOOLONG, ENOENT, EEXIST,
				   ECHILD, EPERM, ENOMEM, EAGAIN,
				   EINTR, ENOBUFS, EADDRINUSE,
				   ECONNREFUSED, ECONNRESET,
				   ETOOMANYREFS, EMSGSIZE, EBADF,
				   EINVAL */
#include <string.h>		/* strdup(), memcpy(),
				   explicit_bzero(), memset(),
				   strcmp(), strlen(), strncpy(),
				   memcmp(), basename() */
#include <argz.h>		/* argz_create(), argz_count(),
				   argz_extract(), argz_next(),
				   argz_add() */
#include <sys/epoll.h>		/* epoll_create1(), EPOLL_CLOEXEC,
				   epoll_ctl(), EPOLL_CTL_ADD,
				   struct epoll_event, EPOLLIN,
				   EPOLLRDHUP, EPOLLOUT,
				   epoll_pwait() */
#include <time.h>		/* struct timespec, clock_gettime(),
				   CLOCK_MONOTONIC */
#include <argp.h>		/* struct argp_option, OPTION_HIDDEN,
				   OPTION_ALIAS, struct argp_state,
				   ARGP_ERR_UNKNOWN, ARGP_KEY_ARGS,
				   struct argp, argp_parse(),
				   ARGP_NO_EXIT */
#include <unistd.h>		/* uid_t, gid_t, close(), pipe2(),
				   fork(), _exit(), dup2(),
				   STDOUT_FILENO, setresgid(),
				   setresuid(), execv(), ssize_t,
				   read(), dup3(), getuid(), dup(),
				   STDERR_FILENO, pause(), write(),
				   rmdir(), unlink(), getpid() */
#include <sys/mman.h>		/* munlock(), mlock() */
#include <fcntl.h>		/* O_CLOEXEC, O_NONBLOCK, fcntl(),
				   F_GETFD, F_GETFL, FD_CLOEXEC,
				   open(), O_WRONLY, O_NOCTTY,
				   O_RDONLY */
#include <sys/wait.h>		/* waitpid(), WNOHANG, WIFEXITED(),
				   WEXITSTATUS() */
#include <limits.h>		/* PIPE_BUF, NAME_MAX, INT_MAX */
#include <sys/inotify.h>	/* inotify_init1(), IN_NONBLOCK,
				   IN_CLOEXEC, inotify_add_watch(),
				   IN_CLOSE_WRITE, IN_MOVED_TO,
				   IN_DELETE, struct inotify_event */
#include <fnmatch.h>		/* fnmatch(), FNM_FILE_NAME */
#include <stdio.h>		/* asprintf(), FILE, fopen(),
				   getline(), sscanf(), feof(),
				   ferror(), fclose(), stderr,
				   rename(), fdopen(), fprintf(),
				   fscanf() */
#include <glib.h>    /* GKeyFile, g_key_file_free(), g_key_file_new(),
			GError, g_key_file_load_from_file(),
			G_KEY_FILE_NONE, TRUE, G_FILE_ERROR_NOENT,
			g_key_file_get_string(), guint64,
			g_key_file_get_uint64(),
			G_KEY_FILE_ERROR_KEY_NOT_FOUND, gconstpointer,
			g_assert_true(), g_assert_nonnull(),
			g_assert_null(), g_assert_false(),
			g_assert_cmpint(), g_assert_cmpuint(),
			g_test_skip(), g_assert_cmpstr(),
			g_test_init(), g_test_add(), g_test_run(),
			GOptionContext, g_option_context_new(),
			g_option_context_set_help_enabled(), FALSE,
			g_option_context_set_ignore_unknown_options(),
			gboolean, GOptionEntry, G_OPTION_ARG_NONE,
			g_option_context_add_main_entries(),
			g_option_context_parse(),
			g_option_context_free(), g_error() */
#include <sys/un.h>		/* struct sockaddr_un, SUN_LEN */
#include <sys/socket.h>		/* AF_LOCAL, socket(), PF_LOCAL,
				   SOCK_DGRAM, SOCK_NONBLOCK,
				   SOCK_CLOEXEC, connect(),
				   struct sockaddr, socklen_t,
				   shutdown(), SHUT_RD, send(),
				   MSG_NOSIGNAL, bind(), recv(),
				   socketpair() */
#include <glob.h>		/* globfree(), glob_t, glob(),
				   GLOB_ERR, GLOB_NOSORT, GLOB_MARK,
				   GLOB_ABORTED, GLOB_NOMATCH,
				   GLOB_NOSPACE */

/* End of includes */

/* Start of declarations of private types and functions */

/* microseconds of CLOCK_MONOTONIC absolute time; 0 means unset */
typedef uintmax_t mono_microsecs;

/* "task_queue" - A queue of tasks to be run */
typedef struct {
  struct task_struct *tasks;	/* Tasks in this queue */
  size_t length;		/* Number of tasks */
  /* Memory allocated for "tasks", in bytes */
  size_t allocated;		
  /* Time when this queue should be run, at the latest */
  mono_microsecs next_run;
} __attribute__((designated_init)) task_queue;

/* "func_type" - A function type for task functions

   I.e. functions for the code which runs when a task is run, all have
   this type */
typedef void (task_func) (const struct task_struct,
			  task_queue *const)
  __attribute__((nonnull));

/* "buffer" - A data buffer for a growing array of bytes

   Used for the "password" variable */
typedef struct {
  char *data;
  size_t length;
  size_t allocated;
} __attribute__((designated_init)) buffer;

/* "string_set" - A set type which can contain strings

   Used by the "cancelled_filenames" variable */
typedef struct {
  char *argz;			/* Do not access these except in */
  size_t argz_len;		/* the string_set_* functions */
} __attribute__((designated_init)) string_set;

/* "task_context" - local variables for tasks

   This data structure distinguishes between different tasks which are
   using the same function.  This data structure is passed to every
   task function when each task is run.

   Note that not every task uses every struct member. */
typedef struct task_struct {
  task_func *const func;	 /* The function run by this task */
  char *const question_filename; /* The question file */
  const pid_t pid;		 /* Mandos client process ID */
  const int epoll_fd;		 /* The epoll set file descriptor */
  bool *const quit_now;		 /* Set to true on fatal errors */
  const int fd;			 /* General purpose file descriptor */
  bool *const mandos_client_exited; /* Set true when client exits */
  buffer *const password;	    /* As read from client process */
  bool *const password_is_read;	    /* "password" is done growing */
  char *filename;		    /* General purpose file name */
  /* A set of strings of all the file names of questions which have
     been cancelled for any reason; tasks pertaining to these question
     files should not be run */
  string_set *const cancelled_filenames;
  const mono_microsecs notafter; /* "NotAfter" from question file */
  /* Updated before each queue run; is compared with queue.next_run */
  const mono_microsecs *const current_time;
} __attribute__((designated_init)) task_context;

/* Declare all our functions here so we can define them in any order
   below.  Note: test functions are *not* declared here, they are
   declared in the test section. */
__attribute__((warn_unused_result))
static bool should_only_run_tests(int *, char **[]);
__attribute__((warn_unused_result, cold))
static bool run_tests(int, char *[]);
static void handle_sigchld(__attribute__((unused)) int sig){}
__attribute__((warn_unused_result, malloc))
task_queue *create_queue(void);
__attribute__((nonnull, warn_unused_result))
bool add_to_queue(task_queue *const, const task_context);
__attribute__((nonnull))
void cleanup_task(const task_context *const);
__attribute__((nonnull))
void cleanup_queue(task_queue *const *const);
__attribute__((pure, nonnull, warn_unused_result))
bool queue_has_question(const task_queue *const);
__attribute__((nonnull))
void cleanup_close(const int *const);
__attribute__((nonnull))
void cleanup_string(char *const *const);
__attribute__((nonnull))
void cleanup_buffer(buffer *const);
__attribute__((pure, nonnull, warn_unused_result))
bool string_set_contains(const string_set, const char *const);
__attribute__((nonnull, warn_unused_result))
bool string_set_add(string_set *const, const char *const);
__attribute__((nonnull))
void string_set_clear(string_set *);
void string_set_swap(string_set *const, string_set *const);
__attribute__((nonnull, warn_unused_result))
bool start_mandos_client(task_queue *const, const int, bool *const,
			 bool *const, buffer *const, bool *const,
			 const struct sigaction *const,
			 const sigset_t, const char *const,
			 const uid_t, const gid_t,
			 const char *const *const);
__attribute__((nonnull))
task_func wait_for_mandos_client_exit;
__attribute__((nonnull))
task_func read_mandos_client_output;
__attribute__((warn_unused_result))
bool add_inotify_dir_watch(task_queue *const, const int, bool *const,
			   buffer *const, const char *const,
			   string_set *, const mono_microsecs *const,
			   bool *const, bool *const);
__attribute__((nonnull))
task_func read_inotify_event;
__attribute__((nonnull))
task_func open_and_parse_question;
__attribute__((nonnull))
task_func cancel_old_question;
__attribute__((nonnull))
task_func connect_question_socket;
__attribute__((nonnull))
task_func send_password_to_socket;
__attribute__((warn_unused_result))
bool add_existing_questions(task_queue *const, const int,
			    buffer *const, string_set *,
			    const mono_microsecs *const,
			    bool *const, bool *const,
			    const char *const);
__attribute__((nonnull, warn_unused_result))
bool wait_for_event(const int, const mono_microsecs,
		    const mono_microsecs);
bool run_queue(task_queue **const, string_set *const, bool *const);
bool clear_all_fds_from_epoll_set(const int);
mono_microsecs get_current_time(void);
__attribute__((nonnull, warn_unused_result))
bool setup_signal_handler(struct sigaction *const);
__attribute__((nonnull))
bool restore_signal_handler(const struct sigaction *const);
__attribute__((nonnull, warn_unused_result))
bool block_sigchld(sigset_t *const);
__attribute__((nonnull))
bool restore_sigmask(const sigset_t *const);
__attribute__((nonnull))
bool parse_arguments(int, char *[], const bool, char **, char **,
		     uid_t *const , gid_t *const, char **, size_t *);

/* End of declarations of private types and functions */

/* Start of "main" section; this section LACKS TESTS!

   Code here should be as simple as possible. */

/* These are required to be global by Argp */
const char *argp_program_version = "password-agent " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";

int main(int argc, char *argv[]){

  /* If the --test option is passed, skip all normal operations and
     instead only run the run_tests() function, which also does all
     its own option parsing, so we don't have to do anything here. */
  if(should_only_run_tests(&argc, &argv)){
    if(run_tests(argc, argv)){
      return EXIT_SUCCESS;	/* All tests successful */
    }
    return EXIT_FAILURE;	/* Some test(s) failed */
  }

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;

  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;

  uid_t user = 0;
  gid_t group = 0;

  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  if(not parse_arguments(argc, argv, true, &agent_directory,
			 &helper_directory, &user, &group,
			 &mandos_argz, &mandos_argz_length)){
    /* This should never happen, since "true" is passed as the third
       argument to parse_arguments() above, which should make
       argp_parse() call exit() if any parsing error occurs. */
    error(EX_USAGE, errno, "Failed to parse arguments");
  }

  const char default_agent_directory[] = "/run/systemd/ask-password";
  const char default_helper_directory[]
    = "/lib/mandos/plugin-helpers";
  const char *const default_argv[]
    = {"/lib/mandos/plugins.d/mandos-client", NULL };

  /* Set variables to default values if unset */
  if(agent_directory == NULL){
    agent_directory = strdup(default_agent_directory);
    if(agent_directory == NULL){
      error(EX_OSERR, errno, "Failed strdup()");
    }
  }
  if(helper_directory == NULL){
    helper_directory = strdup(default_helper_directory);
    if(helper_directory == NULL){
      error(EX_OSERR, errno, "Failed strdup()");
    }
  }
  if(user == 0){
    user = 65534;		/* nobody */
  }
  if(group == 0){
    group = 65534;		/* nogroup */
  }
  /* If parse_opt did not create an argz vector, create one with
     default values */
  if(mandos_argz == NULL){
#ifdef __GNUC__
#pragma GCC diagnostic push
    /* argz_create() takes a non-const argv for some unknown reason -
       argz_create() isn't modifying the strings, just copying them.
       Therefore, this cast to non-const should be safe. */
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    errno = argz_create((char *const *)default_argv, &mandos_argz,
			&mandos_argz_length);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
    if(errno != 0){
      error(EX_OSERR, errno, "Failed argz_create()");
    }
  }
  /* Use argz vector to create a normal argv, usable by execv() */

  char **mandos_argv = malloc((argz_count(mandos_argz,
					  mandos_argz_length)
			       + 1) * sizeof(char *));
  if(mandos_argv == NULL){
    error_t saved_errno = errno;
    free(mandos_argz);
    error(EX_OSERR, saved_errno, "Failed malloc()");
  }
  argz_extract(mandos_argz, mandos_argz_length, mandos_argv);

  sigset_t orig_sigmask;
  if(not block_sigchld(&orig_sigmask)){
    return EX_OSERR;
  }

  struct sigaction old_sigchld_action;
  if(not setup_signal_handler(&old_sigchld_action)){
    return EX_OSERR;
  }

  mono_microsecs current_time = 0;

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if(epoll_fd < 0){
    error(EX_OSERR, errno, "Failed to create epoll set fd");
  }
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  if(queue == NULL){
    error(EX_OSERR, errno, "Failed to create task queue");
  }

  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;

  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};

  /* Add tasks to queue */
  if(not start_mandos_client(queue, epoll_fd, &mandos_client_exited,
  			     &quit_now, &password, &password_is_read,
  			     &old_sigchld_action, orig_sigmask,
			     helper_directory, user, group,
			     (const char *const *)mandos_argv)){
    return EX_OSERR;		/* Error has already been printed */
  }
  /* These variables were only for start_mandos_client() and are not
     needed anymore */
  free(mandos_argv);
  free(mandos_argz);
  mandos_argz = NULL;
  if(not add_inotify_dir_watch(queue, epoll_fd, &quit_now, &password,
  			       agent_directory, &cancelled_filenames,
  			       &current_time, &mandos_client_exited,
  			       &password_is_read)){
    switch(errno){		/* Error has already been printed */
    case EACCES:
    case ENAMETOOLONG:
    case ENOENT:
    case ENOTDIR:
      return EX_OSFILE;
    default:
      return EX_OSERR;
    }
  }
  if(not add_existing_questions(queue, epoll_fd, &password,
				&cancelled_filenames, &current_time,
				&mandos_client_exited,
				&password_is_read, agent_directory)){
    return EXIT_FAILURE;	/* Error has already been printed */
  }

  /* Run queue */
  do {
    current_time = get_current_time();
    if(not wait_for_event(epoll_fd, queue->next_run, current_time)){
      const error_t saved_errno = errno;
      error(EXIT_FAILURE, saved_errno, "Failure while waiting for"
	    " events");
    }

    current_time = get_current_time();
    if(not run_queue(&queue, &cancelled_filenames, &quit_now)){
      const error_t saved_errno = errno;
      error(EXIT_FAILURE, saved_errno, "Failure while running queue");
    }

    /*  When no tasks about questions are left in the queue, break out
	of the loop (and implicitly exit the program) */
  } while(queue_has_question(queue));

  restore_signal_handler(&old_sigchld_action);
  restore_sigmask(&orig_sigmask);

  return EXIT_SUCCESS;
}

__attribute__((warn_unused_result))
mono_microsecs get_current_time(void){
  struct timespec currtime;
  if(clock_gettime(CLOCK_MONOTONIC, &currtime) != 0){
    error(0, errno, "Failed to get current time");
    return 0;
  }
  return ((mono_microsecs)currtime.tv_sec * 1000000) /* seconds */
    + ((mono_microsecs)currtime.tv_nsec / 1000);     /* nanoseconds */
}

/* End of "main" section */

/* Start of regular code section; ALL this code has tests */

__attribute__((nonnull))
bool parse_arguments(int argc, char *argv[], const bool exit_failure,
		     char **agent_directory, char **helper_directory,
		     uid_t *const user, gid_t *const group,
		     char **mandos_argz, size_t *mandos_argz_length){

  const struct argp_option options[] = {
    { .name="agent-directory",.key='d', .arg="DIRECTORY",
      .doc="Systemd password agent directory" },
    { .name="helper-directory",.key=128, .arg="DIRECTORY",
      .doc="Mandos Client password helper directory" },
    { .name="plugin-helper-dir", .key=129, /* From plugin-runner */
      .flags=OPTION_HIDDEN | OPTION_ALIAS },
    { .name="user", .key='u', .arg="USERID",
      .doc="User ID the Mandos Client will use as its unprivileged"
      " user" },
    { .name="userid", .key=130,	/* From plugin--runner */
      .flags=OPTION_HIDDEN | OPTION_ALIAS },
    { .name="group", .key='g', .arg="GROUPID",
      .doc="Group ID the Mandos Client will use as its unprivileged"
      " group" },
    { .name="groupid", .key=131, /* From plugin--runner */
      .flags=OPTION_HIDDEN | OPTION_ALIAS },
    { .name="test", .key=255, /* See should_only_run_tests() */
      .doc="Skip normal operation, and only run self-tests.  See"
      " --test --help.", .group=10, },
    { NULL },
  };

  __attribute__((nonnull(3)))
    error_t parse_opt(int key, char *arg, struct argp_state *state){
    errno = 0;
    switch(key){
    case 'd':			/* --agent-directory */
      *agent_directory = strdup(arg);
      break;
    case 128:			/* --helper-directory */
    case 129:			/* --plugin-helper-dir */
      *helper_directory = strdup(arg);
      break;
    case 'u':			/* --user */
    case 130:			/* --userid */
      {
	char *tmp;
	uintmax_t tmp_id = 0;
	errno = 0;
	tmp_id = (uid_t)strtoumax(arg, &tmp, 10);
	if(errno != 0 or tmp == arg or *tmp != '\0'
	   or tmp_id != (uid_t)tmp_id or (uid_t)tmp_id == 0){
	  return ARGP_ERR_UNKNOWN;
	}
	*user = (uid_t)tmp_id;
	errno = 0;
	break;
      }
    case 'g':			/* --group */
    case 131:			/* --groupid */
      {
	char *tmp;
	uintmax_t tmp_id = 0;
	errno = 0;
	tmp_id = (uid_t)strtoumax(arg, &tmp, 10);
	if(errno != 0 or tmp == arg or *tmp != '\0'
	   or tmp_id != (gid_t)tmp_id or (gid_t)tmp_id == 0){
	  return ARGP_ERR_UNKNOWN;
	}
	*group = (gid_t)tmp_id;
	errno = 0;
	break;
      }
    case ARGP_KEY_ARGS:
      /* Copy arguments into argz vector */
      return argz_create(state->argv + state->next, mandos_argz,
    			 mandos_argz_length);
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return errno;
  }

  const struct argp argp = {
    .options=options,
    .parser=parse_opt,
    .args_doc="[MANDOS_CLIENT [OPTION...]]\n--test",
    .doc = "Mandos password agent -- runs Mandos client as a"
    " systemd password agent",
  };

  errno = argp_parse(&argp, argc, argv,
		     exit_failure ? 0 : ARGP_NO_EXIT, NULL, NULL);

  return errno == 0;
}

__attribute__((nonnull, warn_unused_result))
bool block_sigchld(sigset_t *const orig_sigmask){
  sigset_t sigchld_sigmask;
  if(sigemptyset(&sigchld_sigmask) < 0){
    error(0, errno, "Failed to empty signal set");
    return false;
  }
  if(sigaddset(&sigchld_sigmask, SIGCHLD) < 0){
    error(0, errno, "Failed to add SIGCHLD to signal set");
    return false;
  }
  if(pthread_sigmask(SIG_BLOCK, &sigchld_sigmask, orig_sigmask) != 0){
    error(0, errno, "Failed to block SIGCHLD signal");
    return false;
  }
  return true;
}

__attribute__((nonnull, warn_unused_result, const))
bool restore_sigmask(const sigset_t *const orig_sigmask){
  if(pthread_sigmask(SIG_SETMASK, orig_sigmask, NULL) != 0){
    error(0, errno, "Failed to restore blocked signals");
    return false;
  }
  return true;
}

__attribute__((nonnull, warn_unused_result))
bool setup_signal_handler(struct sigaction *const old_sigchld_action){
  struct sigaction sigchld_action = {
    .sa_handler=handle_sigchld,
    .sa_flags=SA_RESTART | SA_NOCLDSTOP,
  };
  /* Set all signals in "sa_mask" struct member; this makes all
     signals automatically blocked during signal handler */
  if(sigfillset(&sigchld_action.sa_mask) != 0){
    error(0, errno, "Failed to do sigfillset()");
    return false;
  }
  if(sigaction(SIGCHLD, &sigchld_action, old_sigchld_action) != 0){
    error(0, errno, "Failed to set SIGCHLD signal handler");
    return false;
  }
  return true;
}

__attribute__((nonnull, warn_unused_result))
bool restore_signal_handler(const struct sigaction *const
			    old_sigchld_action){
  if(sigaction(SIGCHLD, old_sigchld_action, NULL) != 0){
    error(0, errno, "Failed to restore signal handler");
    return false;
  }
  return true;
}

__attribute__((warn_unused_result, malloc))
task_queue *create_queue(void){
  task_queue *queue = malloc(sizeof(task_queue));
  if(queue){
    queue->tasks = NULL;
    queue->length = 0;
    queue->allocated = 0;
    queue->next_run = 0;
  }
  return queue;
}

__attribute__((nonnull, warn_unused_result))
bool add_to_queue(task_queue *const queue, const task_context task){
  const size_t needed_size = sizeof(task_context)*(queue->length + 1);
  if(needed_size > (queue->allocated)){
    task_context *const new_tasks = realloc(queue->tasks,
					    needed_size);
    if(new_tasks == NULL){
      error(0, errno, "Failed to allocate %" PRIuMAX
	    " bytes for queue->tasks", (uintmax_t)needed_size);
      return false;
    }
    queue->tasks = new_tasks;
    queue->allocated = needed_size;
  }
  /* Using memcpy here is necessary because doing */
  /* queue->tasks[queue->length++] = task; */
  /* would violate const-ness of task members */
  memcpy(&(queue->tasks[queue->length++]), &task,
	 sizeof(task_context));
  return true;
}

__attribute__((nonnull))
void cleanup_task(const task_context *const task){
  const error_t saved_errno = errno;
  /* free and close all task data */
  free(task->question_filename);
  if(task->filename != task->question_filename){
    free(task->filename);
  }
  if(task->pid > 0){
    kill(task->pid, SIGTERM);
  }
  if(task->fd > 0){
    close(task->fd);
  }
  errno = saved_errno;
}

__attribute__((nonnull))
void free_queue(task_queue *const queue){
  free(queue->tasks);
  free(queue);
}

__attribute__((nonnull))
void cleanup_queue(task_queue *const *const queue){
  if(*queue == NULL){
    return;
  }
  for(size_t i = 0; i < (*queue)->length; i++){
    const task_context *const task = ((*queue)->tasks)+i;
    cleanup_task(task);
  }
  free_queue(*queue);
}

__attribute__((pure, nonnull, warn_unused_result))
bool queue_has_question(const task_queue *const queue){
  for(size_t i=0; i < queue->length; i++){
    if(queue->tasks[i].question_filename != NULL){
      return true;
    }
  }
  return false;
}

__attribute__((nonnull))
void cleanup_close(const int *const fd){
  const error_t saved_errno = errno;
  close(*fd);
  errno = saved_errno;
}

__attribute__((nonnull))
void cleanup_string(char *const *const ptr){
  free(*ptr);
}

__attribute__((nonnull))
void cleanup_buffer(buffer *buf){
  if(buf->allocated > 0){
#if defined(__GLIBC_PREREQ) and __GLIBC_PREREQ(2, 25)
    explicit_bzero(buf->data, buf->allocated);
#else
    memset(buf->data, '\0', buf->allocated);
#endif
  }
  if(buf->data != NULL){
    if(munlock(buf->data, buf->allocated) != 0){
      error(0, errno, "Failed to unlock memory of old buffer");
    }
    free(buf->data);
    buf->data = NULL;
  }
  buf->length = 0;
  buf->allocated = 0;
}

__attribute__((pure, nonnull, warn_unused_result))
bool string_set_contains(const string_set set, const char *const str){
  for(const char *s = set.argz; s != NULL and set.argz_len > 0;
      s = argz_next(set.argz, set.argz_len, s)){
    if(strcmp(s, str) == 0){
      return true;
    }
  }
  return false;
}

__attribute__((nonnull, warn_unused_result))
bool string_set_add(string_set *const set, const char *const str){
  if(string_set_contains(*set, str)){
    return true;
  }
  error_t error = argz_add(&set->argz, &set->argz_len, str);
  if(error == 0){
    return true;
  }
  errno = error;
  return false;
}

__attribute__((nonnull))
void string_set_clear(string_set *set){
  free(set->argz);
  set->argz = NULL;
  set->argz_len = 0;
}

__attribute__((nonnull))
void string_set_swap(string_set *const set1, string_set *const set2){
  /* Swap contents of two string sets */
  {
    char *const tmp_argz = set1->argz;
    set1->argz = set2->argz;
    set2->argz = tmp_argz;
  }
  {
    const size_t tmp_argz_len = set1->argz_len;
    set1->argz_len = set2->argz_len;
    set2->argz_len = tmp_argz_len;
  }
}

__attribute__((nonnull, warn_unused_result))
bool start_mandos_client(task_queue *const queue,
			 const int epoll_fd,
			 bool *const mandos_client_exited,
			 bool *const quit_now, buffer *const password,
			 bool *const password_is_read,
			 const struct sigaction *const
			 old_sigchld_action, const sigset_t sigmask,
			 const char *const helper_directory,
			 const uid_t user, const gid_t group,
			 const char *const *const argv){
  int pipefds[2];
  if(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK) != 0){
    error(0, errno, "Failed to pipe2(..., O_CLOEXEC | O_NONBLOCK)");
    return false;
  }

  const pid_t pid = fork();
  if(pid == 0){
    if(not restore_signal_handler(old_sigchld_action)){
      _exit(EXIT_FAILURE);
    }
    if(not restore_sigmask(&sigmask)){
      _exit(EXIT_FAILURE);
    }
    if(close(pipefds[0]) != 0){
      error(0, errno, "Failed to close() parent pipe fd");
      _exit(EXIT_FAILURE);
    }
    if(dup2(pipefds[1], STDOUT_FILENO) == -1){
      error(0, errno, "Failed to dup2() pipe fd to stdout");
      _exit(EXIT_FAILURE);
    }
    if(close(pipefds[1]) != 0){
      error(0, errno, "Failed to close() old child pipe fd");
      _exit(EXIT_FAILURE);
    }
    if(setenv("MANDOSPLUGINHELPERDIR", helper_directory, 1) != 0){
      error(0, errno, "Failed to setenv(\"MANDOSPLUGINHELPERDIR\","
	    " \"%s\", 1)", helper_directory);
      _exit(EXIT_FAILURE);
    }
    if(group != 0 and setresgid(group, 0, 0) == -1){
      error(0, errno, "Failed to setresgid(-1, %" PRIuMAX ", %"
	    PRIuMAX")", (uintmax_t)group, (uintmax_t)group);
      _exit(EXIT_FAILURE);
    }
    if(user != 0 and setresuid(user, 0, 0) == -1){
      error(0, errno, "Failed to setresuid(-1, %" PRIuMAX ", %"
	    PRIuMAX")", (uintmax_t)user, (uintmax_t)user);
      _exit(EXIT_FAILURE);
    }
#ifdef __GNUC__
#pragma GCC diagnostic push
    /* For historical reasons, the "argv" argument to execv() is not
       const, but it is safe to override this. */
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    execv(argv[0], (char **)argv);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
    error(0, errno, "execv(\"%s\", ...) failed", argv[0]);
    _exit(EXIT_FAILURE);
  }
  close(pipefds[1]);

  if(not add_to_queue(queue, (task_context){
	.func=wait_for_mandos_client_exit,
	.pid=pid,
	.mandos_client_exited=mandos_client_exited,
	.quit_now=quit_now,
      })){
    error(0, errno, "Failed to add wait_for_mandos_client to queue");
    close(pipefds[0]);
    return false;
  }

  const int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipefds[0],
			    &(struct epoll_event)
			    { .events=EPOLLIN | EPOLLRDHUP });
  if(ret != 0 and errno != EEXIST){
    error(0, errno, "Failed to add file descriptor to epoll set");
    close(pipefds[0]);
    return false;
  }

  return add_to_queue(queue, (task_context){
      .func=read_mandos_client_output,
      .epoll_fd=epoll_fd,
      .fd=pipefds[0],
      .quit_now=quit_now,
      .password=password,
      .password_is_read=password_is_read,
    });
}

__attribute__((nonnull))
void wait_for_mandos_client_exit(const task_context task,
				 task_queue *const queue){
  const pid_t pid = task.pid;
  bool *const mandos_client_exited = task.mandos_client_exited;
  bool *const quit_now = task.quit_now;

  int status;
  switch(waitpid(pid, &status, WNOHANG)){
  case 0:			/* Not exited yet */
    if(not add_to_queue(queue, task)){
      error(0, errno, "Failed to add myself to queue");
      *quit_now = true;
    }
    break;
  case -1:			/* Error */
    error(0, errno, "waitpid(%" PRIdMAX ") failed", (intmax_t)pid);
    if(errno != ECHILD){
      kill(pid, SIGTERM);
    }
    *quit_now = true;
    break;
  default:			/* Has exited */
    *mandos_client_exited = true;
    if((not WIFEXITED(status))
       or (WEXITSTATUS(status) != EXIT_SUCCESS)){
      error(0, 0, "Mandos client failed or was killed");
      *quit_now = true;
    }
  }
}

__attribute__((nonnull))
void read_mandos_client_output(const task_context task,
			       task_queue *const queue){
  buffer *const password = task.password;
  bool *const quit_now = task.quit_now;
  bool *const password_is_read = task.password_is_read;
  const int fd = task.fd;
  const int epoll_fd = task.epoll_fd;

  const size_t new_potential_size = (password->length + PIPE_BUF);
  if(password->allocated < new_potential_size){
    char *const new_buffer = calloc(new_potential_size, 1);
    if(new_buffer == NULL){
      error(0, errno, "Failed to allocate %" PRIuMAX
	    " bytes for password", (uintmax_t)new_potential_size);
      *quit_now = true;
      close(fd);
      return;
    }
    if(mlock(new_buffer, new_potential_size) != 0){
      /* Warn but do not treat as fatal error */
      if(errno != EPERM and errno != ENOMEM){
	error(0, errno, "Failed to lock memory for password");
      }
    }
    if(password->length > 0){
      memcpy(new_buffer, password->data, password->length);
#if defined(__GLIBC_PREREQ) and __GLIBC_PREREQ(2, 25)
      explicit_bzero(password->data, password->allocated);
#else
      memset(password->data, '\0', password->allocated);
#endif
    }
    if(password->data != NULL){
      if(munlock(password->data, password->allocated) != 0){
	error(0, errno, "Failed to unlock memory of old buffer");
      }
      free(password->data);
    }
    password->data = new_buffer;
    password->allocated = new_potential_size;
  }

  const ssize_t read_length = read(fd, password->data
				   + password->length, PIPE_BUF);

  if(read_length == 0){	/* EOF */
    *password_is_read = true;
    close(fd);
    return;
  }
  if(read_length < 0 and errno != EAGAIN){ /* Actual error */
    error(0, errno, "Failed to read password from Mandos client");
    *quit_now = true;
    close(fd);
    return;
  }
  if(read_length > 0){		/* Data has been read */
    password->length += (size_t)read_length;
  }

  /* Either data was read, or EAGAIN was indicated, meaning no data
     available yet */

  /* Re-add the fd to the epoll set */
  const int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd,
			    &(struct epoll_event)
			    { .events=EPOLLIN | EPOLLRDHUP });
  if(ret != 0 and errno != EEXIST){
    error(0, errno, "Failed to re-add file descriptor to epoll set");
    *quit_now = true;
    close(fd);
    return;
  }

  /* Re-add myself to the queue */
  if(not add_to_queue(queue, task)){
    error(0, errno, "Failed to add myself to queue");
    *quit_now = true;
    close(fd);
  }
}

__attribute__((nonnull, warn_unused_result))
bool add_inotify_dir_watch(task_queue *const queue,
			   const int epoll_fd, bool *const quit_now,
			   buffer *const password,
			   const char *const dir,
			   string_set *cancelled_filenames,
			   const mono_microsecs *const current_time,
			   bool *const mandos_client_exited,
			   bool *const password_is_read){
  const int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if(fd == -1){
    error(0, errno, "Failed to create inotify instance");
    return false;
  }

  if(inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO
		       | IN_MOVED_FROM| IN_DELETE | IN_EXCL_UNLINK
		       | IN_ONLYDIR)
     == -1){
    error(0, errno, "Failed to create inotify watch on %s", dir);
    return false;
  }

  /* Add the inotify fd to the epoll set */
  const int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd,
			    &(struct epoll_event)
			    { .events=EPOLLIN | EPOLLRDHUP });
  if(ret != 0 and errno != EEXIST){
    error(0, errno, "Failed to add file descriptor to epoll set");
    close(fd);
    return false;
  }

  const task_context read_inotify_event_task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .quit_now=quit_now,
    .password=password,
    .fd=fd,
    .filename=strdup(dir),
    .cancelled_filenames=cancelled_filenames,
    .current_time=current_time,
    .mandos_client_exited=mandos_client_exited,
    .password_is_read=password_is_read,
  };
  if(read_inotify_event_task.filename == NULL){
    error(0, errno, "Failed to strdup(\"%s\")", dir);
    close(fd);
    return false;
  }

  return add_to_queue(queue, read_inotify_event_task);
}

__attribute__((nonnull))
void read_inotify_event(const task_context task,
			task_queue *const queue){
  const int fd = task.fd;
  const int epoll_fd = task.epoll_fd;
  char *const filename = task.filename;
  bool *quit_now = task.quit_now;
  buffer *const password = task.password;
  string_set *const cancelled_filenames = task.cancelled_filenames;
  const mono_microsecs *const current_time = task.current_time;
  bool *const mandos_client_exited = task.mandos_client_exited;
  bool *const password_is_read = task.password_is_read;

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const ssize_t read_length = read(fd, ievent, ievent_size);
  if(read_length == 0){	/* EOF */
    error(0, 0, "Got EOF from inotify fd for directory %s", filename);
    *quit_now = true;
    cleanup_task(&task);
    return;
  }
  if(read_length < 0 and errno != EAGAIN){ /* Actual error */
    error(0, errno, "Failed to read from inotify fd for directory %s",
	  filename);
    *quit_now = true;
    cleanup_task(&task);
    return;
  }
  if(read_length > 0		/* Data has been read */
     and fnmatch("ask.*", ievent->name, FNM_FILE_NAME) == 0){
    char *question_filename = NULL;
    const ssize_t question_filename_length
      = asprintf(&question_filename, "%s/%s", filename, ievent->name);
    if(question_filename_length < 0){
      error(0, errno, "Failed to create file name from directory name"
	    " %s and file name %s", filename, ievent->name);
    } else {
      if(ievent->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)){
	if(not add_to_queue(queue, (task_context){
	      .func=open_and_parse_question,
	      .epoll_fd=epoll_fd,
	      .question_filename=question_filename,
	      .filename=question_filename,
	      .password=password,
	      .cancelled_filenames=cancelled_filenames,
	      .current_time=current_time,
	      .mandos_client_exited=mandos_client_exited,
	      .password_is_read=password_is_read,
	    })){
	  error(0, errno, "Failed to add open_and_parse_question task"
		" for file name %s to queue", filename);
	} else {
	  /* Force the added task (open_and_parse_question) to run
	     immediately */
	  queue->next_run = 1;
	}
      } else if(ievent->mask & (IN_MOVED_FROM | IN_DELETE)){
	if(not string_set_add(cancelled_filenames,
			      question_filename)){
	  error(0, errno, "Could not add question %s to"
		" cancelled_questions", question_filename);
	  *quit_now = true;
	  free(question_filename);
	  cleanup_task(&task);
	  return;
	}
	free(question_filename);
      }
    }
  }

  /* Either data was read, or EAGAIN was indicated, meaning no data
     available yet */

  /* Re-add myself to the queue */
  if(not add_to_queue(queue, task)){
    error(0, errno, "Failed to re-add read_inotify_event(%s) to"
	  " queue", filename);
    *quit_now = true;
    cleanup_task(&task);
    return;
  }

  /* Re-add the fd to the epoll set */
  const int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd,
			    &(struct epoll_event)
			    { .events=EPOLLIN | EPOLLRDHUP });
  if(ret != 0 and errno != EEXIST){
    error(0, errno, "Failed to re-add inotify file descriptor %d for"
	  " directory %s to epoll set", fd, filename);
    /* Force the added task (read_inotify_event) to run again, at most
       one second from now */
    if((queue->next_run == 0)
       or (queue->next_run > (*current_time + 1000000))){
      queue->next_run = *current_time + 1000000;
    }
  }
}

__attribute__((nonnull))
void open_and_parse_question(const task_context task,
			     task_queue *const queue){
  __attribute__((cleanup(cleanup_string)))
    char *question_filename = task.question_filename;
  const int epoll_fd = task.epoll_fd;
  buffer *const password = task.password;
  string_set *const cancelled_filenames = task.cancelled_filenames;
  const mono_microsecs *const current_time = task.current_time;
  bool *const mandos_client_exited = task.mandos_client_exited;
  bool *const password_is_read = task.password_is_read;

  /* We use the GLib "Key-value file parser" functions to parse the
     question file.  See <https://www.freedesktop.org/wiki/Software
     /systemd/PasswordAgents/> for specification of contents */
  __attribute__((nonnull))
    void cleanup_g_key_file(GKeyFile **key_file){
    if(*key_file != NULL){
      g_key_file_free(*key_file);
    }
  }

  __attribute__((cleanup(cleanup_g_key_file)))
    GKeyFile *key_file = g_key_file_new();
  if(key_file == NULL){
    error(0, errno, "Failed g_key_file_new() for \"%s\"",
	  question_filename);
    return;
  }
  GError *glib_error = NULL;
  if(g_key_file_load_from_file(key_file, question_filename,
			       G_KEY_FILE_NONE, &glib_error) != TRUE){
    /* If a file was removed, we should ignore it, so */
    /* only show error message if file actually existed */
    if(glib_error->code != G_FILE_ERROR_NOENT){
      error(0, 0, "Failed to load question data from file \"%s\": %s",
	    question_filename, glib_error->message);
    }
    return;
  }

  __attribute__((cleanup(cleanup_string)))
    char *socket_name = g_key_file_get_string(key_file, "Ask",
					      "Socket",
					      &glib_error);
  if(socket_name == NULL){
    error(0, 0, "Question file \"%s\" did not contain \"Socket\": %s",
	  question_filename, glib_error->message);
    return;
  }

  if(strlen(socket_name) == 0){
    error(0, 0, "Question file \"%s\" had empty \"Socket\" value",
	  question_filename);
    return;
  }

  const guint64 pid = g_key_file_get_uint64(key_file, "Ask", "PID",
					    &glib_error);
  if(glib_error != NULL){
    error(0, 0, "Question file \"%s\" contained bad \"PID\": %s",
	  question_filename, glib_error->message);
    return;
  }

  if((pid != (guint64)((pid_t)pid))
     or (kill((pid_t)pid, 0) != 0)){
    error(0, 0, "PID %" PRIuMAX " in question file \"%s\" is bad or"
	  " does not exist", (uintmax_t)pid, question_filename);
    return;
  }

  guint64 notafter = g_key_file_get_uint64(key_file, "Ask",
					   "NotAfter", &glib_error);
  if(glib_error != NULL){
    if(glib_error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND){
      error(0, 0, "Question file \"%s\" contained bad \"NotAfter\":"
	    " %s", question_filename, glib_error->message);
    }
    notafter = 0;
  }
  if(notafter != 0){
    if(queue->next_run == 0 or (queue->next_run > notafter)){
      queue->next_run = notafter;
    }
    if(*current_time >= notafter){
      return;
    }
  }

  const task_context connect_question_socket_task = {
    .func=connect_question_socket,
    .question_filename=strdup(question_filename),
    .epoll_fd=epoll_fd,
    .password=password,
    .filename=strdup(socket_name),
    .cancelled_filenames=task.cancelled_filenames,
    .mandos_client_exited=mandos_client_exited,
    .password_is_read=password_is_read,
    .current_time=current_time,
  };
  if(connect_question_socket_task.question_filename == NULL
     or connect_question_socket_task.filename == NULL
     or not add_to_queue(queue, connect_question_socket_task)){
    error(0, errno, "Failed to add connect_question_socket for socket"
	  " %s (from \"%s\") to queue", socket_name,
	  question_filename);
    cleanup_task(&connect_question_socket_task);
    return;
  }
  /* Force the added task (connect_question_socket) to run
     immediately */
  queue->next_run = 1;

  if(notafter > 0){
    char *const dup_filename = strdup(question_filename);
    const task_context cancel_old_question_task = {
      .func=cancel_old_question,
      .question_filename=dup_filename,
      .notafter=notafter,
      .filename=dup_filename,
      .cancelled_filenames=cancelled_filenames,
      .current_time=current_time,
    };
    if(cancel_old_question_task.question_filename == NULL
       or not add_to_queue(queue, cancel_old_question_task)){
      error(0, errno, "Failed to add cancel_old_question for file "
	    "\"%s\" to queue", question_filename);
      cleanup_task(&cancel_old_question_task);
      return;
    }
  }
}

__attribute__((nonnull))
void cancel_old_question(const task_context task,
			 task_queue *const queue){
  char *const question_filename = task.question_filename;
  string_set *const cancelled_filenames = task.cancelled_filenames;
  const mono_microsecs notafter = task.notafter;
  const mono_microsecs *const current_time = task.current_time;

  if(*current_time >= notafter){
    if(not string_set_add(cancelled_filenames, question_filename)){
      error(0, errno, "Failed to cancel question for file %s",
	    question_filename);
    }
    cleanup_task(&task);
    return;
  }

  if(not add_to_queue(queue, task)){
    error(0, errno, "Failed to add cancel_old_question for file "
	  "%s to queue", question_filename);
    cleanup_task(&task);
    return;
  }

  if((queue->next_run == 0) or (queue->next_run > notafter)){
    queue->next_run = notafter;
  }
}

__attribute__((nonnull))
void connect_question_socket(const task_context task,
			     task_queue *const queue){
  char *const question_filename = task.question_filename;
  char *const filename = task.filename;
  const int epoll_fd = task.epoll_fd;
  buffer *const password = task.password;
  string_set *const cancelled_filenames = task.cancelled_filenames;
  bool *const mandos_client_exited = task.mandos_client_exited;
  bool *const password_is_read = task.password_is_read;
  const mono_microsecs *const current_time = task.current_time;

  struct sockaddr_un sock_name = { .sun_family=AF_LOCAL };

  if(sizeof(sock_name.sun_path) <= strlen(filename)){
    error(0, 0, "Socket filename is larger than"
	  " sizeof(sockaddr_un.sun_path); %" PRIuMAX ": \"%s\"",
	  (uintmax_t)sizeof(sock_name.sun_path), filename);
    if(not string_set_add(cancelled_filenames, question_filename)){
      error(0, errno, "Failed to cancel question for file %s",
	    question_filename);
    }
    cleanup_task(&task);
    return;
  }

  const int fd = socket(PF_LOCAL, SOCK_DGRAM
			| SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if(fd < 0){
    error(0, errno,
	  "Failed to create socket(PF_LOCAL, SOCK_DGRAM, 0)");
    if(not add_to_queue(queue, task)){
      error(0, errno, "Failed to add connect_question_socket for file"
            " \"%s\" and socket \"%s\" to queue", question_filename,
	    filename);
      cleanup_task(&task);
    } else {
      /* Force the added task (connect_question_socket) to run
	 immediately */
      queue->next_run = 1;
    }
    return;
  }

  strncpy(sock_name.sun_path, filename, sizeof(sock_name.sun_path));
  if(connect(fd, (struct sockaddr *)&sock_name,
	     (socklen_t)SUN_LEN(&sock_name)) != 0){
    error(0, errno, "Failed to connect socket to \"%s\"", filename);
    if(not add_to_queue(queue, task)){
      error(0, errno, "Failed to add connect_question_socket for file"
            " \"%s\" and socket \"%s\" to queue", question_filename,
	    filename);
      cleanup_task(&task);
    } else {
      /* Force the added task (connect_question_socket) to run again,
	 at most one second from now */
      if((queue->next_run == 0)
	 or (queue->next_run > (*current_time + 1000000))){
	queue->next_run = *current_time + 1000000;
      }
    }
    return;
  }

  /* Not necessary, but we can try, and merely warn on failure */
  if(shutdown(fd, SHUT_RD) != 0){
    error(0, errno, "Failed to shutdown reading from socket \"%s\"",
	  filename);
  }

  /* Add the fd to the epoll set */
  if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd,
	       &(struct epoll_event){ .events=EPOLLOUT })
     != 0){
    error(0, errno, "Failed to add inotify file descriptor %d for"
	  " socket %s to epoll set", fd, filename);
    if(not add_to_queue(queue, task)){
      error(0, errno, "Failed to add connect_question_socket for file"
            " \"%s\" and socket \"%s\" to queue", question_filename,
	    filename);
      cleanup_task(&task);
    } else {
      /* Force the added task (connect_question_socket) to run again,
	 at most one second from now */
      if((queue->next_run == 0)
	 or (queue->next_run > (*current_time + 1000000))){
	queue->next_run = *current_time + 1000000;
      }
    }
    return;
  }

  /* add task send_password_to_socket to queue */
  const task_context send_password_to_socket_task = {
    .func=send_password_to_socket,
    .question_filename=question_filename,
    .filename=filename,
    .epoll_fd=epoll_fd,
    .fd=fd,
    .password=password,
    .cancelled_filenames=cancelled_filenames,
    .mandos_client_exited=mandos_client_exited,
    .password_is_read=password_is_read,
    .current_time=current_time,
  };

  if(not add_to_queue(queue, send_password_to_socket_task)){
    error(0, errno, "Failed to add send_password_to_socket for"
	  " file \"%s\" and socket \"%s\" to queue",
	  question_filename, filename);
    cleanup_task(&send_password_to_socket_task);
  }
}

__attribute__((nonnull))
void send_password_to_socket(const task_context task,
			     task_queue *const queue){
  char *const question_filename=task.question_filename;
  char *const filename=task.filename;
  const int epoll_fd=task.epoll_fd;
  const int fd=task.fd;
  buffer *const password=task.password;
  string_set *const cancelled_filenames=task.cancelled_filenames;
  bool *const mandos_client_exited = task.mandos_client_exited;
  bool *const password_is_read = task.password_is_read;
  const mono_microsecs *const current_time = task.current_time;

  if(*mandos_client_exited and *password_is_read){

    const size_t send_buffer_length = password->length + 2;
    char *send_buffer = malloc(send_buffer_length);
    if(send_buffer == NULL){
      error(0, errno, "Failed to allocate send_buffer");
    } else {
      if(mlock(send_buffer, send_buffer_length) != 0){
	/* Warn but do not treat as fatal error */
	if(errno != EPERM and errno != ENOMEM){
	  error(0, errno, "Failed to lock memory for password"
		" buffer");
	}
      }
      /* “[…] send a single datagram to the socket consisting of the
	 password string either prefixed with "+" or with "-"
	 depending on whether the password entry was successful or
	 not. You may but don't have to include a final NUL byte in
	 your message.

	 — <https://www.freedesktop.org/wiki/Software/systemd/
	 PasswordAgents/> (Wed 08 Oct 2014 02:14:28 AM UTC)
      */
      send_buffer[0] = '+';	/* Prefix with "+" */
      /* Always add an extra NUL */
      send_buffer[password->length + 1] = '\0';
      if(password->length > 0){
	memcpy(send_buffer + 1, password->data, password->length);
      }
      errno = 0;
      ssize_t ssret = send(fd, send_buffer, send_buffer_length,
			   MSG_NOSIGNAL);
      const error_t saved_errno = errno;
#if defined(__GLIBC_PREREQ) and __GLIBC_PREREQ(2, 25)
      explicit_bzero(send_buffer, send_buffer_length);
#else
      memset(send_buffer, '\0', send_buffer_length);
#endif
      if(munlock(send_buffer, send_buffer_length) != 0){
	error(0, errno, "Failed to unlock memory of send buffer");
      }
      free(send_buffer);
      if(ssret < 0 or ssret < (ssize_t)send_buffer_length){
	switch(saved_errno){
	case EINTR:
	case ENOBUFS:
	case ENOMEM:
	case EADDRINUSE:
	case ECONNREFUSED:
	case ECONNRESET:
	case ENOENT:
	case ETOOMANYREFS:
	case EAGAIN:
	  /* Retry, below */
	  break;
	case EMSGSIZE:
	  error(0, 0, "Password of size %" PRIuMAX " is too big",
		(uintmax_t)password->length);
#if __GNUC__ < 7
	  /* FALLTHROUGH */
#else
	  __attribute__((fallthrough));
#endif
	case 0:
	  if(ssret >= 0 and ssret < (ssize_t)send_buffer_length){
	    error(0, 0, "Password only partially sent to socket");
	  }
#if __GNUC__ < 7
	  /* FALLTHROUGH */
#else
	  __attribute__((fallthrough));
#endif
	default:
	  error(0, saved_errno, "Failed to send() to socket %s",
		filename);
	  if(not string_set_add(cancelled_filenames,
				question_filename)){
	    error(0, errno, "Failed to cancel question for file %s",
		  question_filename);
	  }
	  cleanup_task(&task);
	  return;
	}
      } else {
	/* Success */
	cleanup_task(&task);
	return;
      }
    }
  }

  /* We failed or are not ready yet; retry later */

  if(not add_to_queue(queue, task)){
    error(0, errno, "Failed to add send_password_to_socket for"
	  " file %s and socket %s to queue", question_filename,
	  filename);
    cleanup_task(&task);
  }

  /* Add the fd to the epoll set */
  if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd,
	       &(struct epoll_event){ .events=EPOLLOUT })
     != 0){
    error(0, errno, "Failed to add socket file descriptor %d for"
	  " socket %s to epoll set", fd, filename);
    /* Force the added task (send_password_to_socket) to run again, at
       most one second from now */
    if((queue->next_run == 0)
       or (queue->next_run > (*current_time + 1000000))){
      queue->next_run = *current_time + 1000000;
    }
  }
}

__attribute__((warn_unused_result))
bool add_existing_questions(task_queue *const queue,
			    const int epoll_fd,
			    buffer *const password,
			    string_set *cancelled_filenames,
			    const mono_microsecs *const current_time,
			    bool *const mandos_client_exited,
			    bool *const password_is_read,
			    const char *const dirname){
  __attribute__((cleanup(cleanup_string)))
    char *dir_pattern = NULL;
  const int ret = asprintf(&dir_pattern, "%s/ask.*", dirname);
  if(ret < 0 or dir_pattern == NULL){
    error(0, errno, "Could not create glob pattern for directory %s",
	  dirname);
    return false;
  }
  __attribute__((cleanup(globfree)))
    glob_t question_filenames = {};
  switch(glob(dir_pattern, GLOB_ERR | GLOB_NOSORT | GLOB_MARK,
	      NULL, &question_filenames)){
  case GLOB_ABORTED:
  default:
    error(0, errno, "Failed to open directory %s", dirname);
    return false;
  case GLOB_NOMATCH:
    error(0, errno, "There are no question files in %s", dirname);
    return false;
  case GLOB_NOSPACE:
    error(0, errno, "Could not allocate memory for question file"
	  " names in %s", dirname);
#if __GNUC__ < 7
    /* FALLTHROUGH */
#else
    __attribute__((fallthrough));
#endif
  case 0:
    for(size_t i = 0; i < question_filenames.gl_pathc; i++){
      char *const question_filename = strdup(question_filenames
					     .gl_pathv[i]);
      const task_context task = {
	.func=open_and_parse_question,
	.epoll_fd=epoll_fd,
	.question_filename=question_filename,
	.filename=question_filename,
	.password=password,
	.cancelled_filenames=cancelled_filenames,
	.current_time=current_time,
	.mandos_client_exited=mandos_client_exited,
	.password_is_read=password_is_read,
      };

      if(question_filename == NULL
	 or not add_to_queue(queue, task)){
	error(0, errno, "Failed to add open_and_parse_question for"
	      " file %s to queue",
	      question_filenames.gl_pathv[i]);
	free(question_filename);
      } else {
	queue->next_run = 1;
      }
    }
    return true;
  }
}

__attribute__((nonnull, warn_unused_result))
bool wait_for_event(const int epoll_fd,
		    const mono_microsecs queue_next_run,
		    const mono_microsecs current_time){
  __attribute__((const))
    int milliseconds_to_wait(const mono_microsecs currtime,
			     const mono_microsecs nextrun){
    if(currtime >= nextrun){
      return 0;
    }
    const uintmax_t wait_time_ms = (nextrun - currtime) / 1000;
    if(wait_time_ms > (uintmax_t)INT_MAX){
      return INT_MAX;
    }
    return (int)wait_time_ms;
  }

  const int wait_time_ms = milliseconds_to_wait(current_time,
						queue_next_run);

  /* Prepare unblocking of SIGCHLD during epoll_pwait */
  sigset_t temporary_unblocked_sigmask;
  /* Get current signal mask */
  if(pthread_sigmask(-1, NULL, &temporary_unblocked_sigmask) != 0){
    return false;
  }
  /* Remove SIGCHLD from the signal mask */
  if(sigdelset(&temporary_unblocked_sigmask, SIGCHLD) != 0){
    return false;
  }
  struct epoll_event events[8]; /* Ignored */
  int ret = epoll_pwait(epoll_fd, events,
			sizeof(events) / sizeof(struct epoll_event),
			queue_next_run == 0 ? -1 : (int)wait_time_ms,
			&temporary_unblocked_sigmask);
  if(ret < 0 and errno != EINTR){
    error(0, errno, "Failed epoll_pwait(epfd=%d, ..., timeout=%d,"
	  " ...", epoll_fd,
	  queue_next_run == 0 ? -1 : (int)wait_time_ms);
    return false;
  }
  return clear_all_fds_from_epoll_set(epoll_fd);
}

bool clear_all_fds_from_epoll_set(const int epoll_fd){
  /* Create a new empty epoll set */
  __attribute__((cleanup(cleanup_close)))
    const int new_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if(new_epoll_fd < 0){
    return false;
  }
  /* dup3() the new epoll set fd over the old one, replacing it */
  if(dup3(new_epoll_fd, epoll_fd, O_CLOEXEC) < 0){
    return false;
  }
  return true;
}

__attribute__((nonnull, warn_unused_result))
bool run_queue(task_queue **const queue,
	       string_set *const cancelled_filenames,
	       bool *const quit_now){

  task_queue *new_queue = create_queue();
  if(new_queue == NULL){
    return false;
  }

  __attribute__((cleanup(string_set_clear)))
    string_set old_cancelled_filenames = {};
  string_set_swap(cancelled_filenames, &old_cancelled_filenames);

  /* Declare i outside the for loop, since we might need i after the
     loop in case we aborted in the middle */
  size_t i;
  for(i=0; i < (*queue)->length and not *quit_now; i++){
    task_context *const task = &((*queue)->tasks[i]);
    const char *const question_filename = task->question_filename;
    /* Skip any task referencing a cancelled question filename */
    if(question_filename != NULL
       and string_set_contains(old_cancelled_filenames,
    			       question_filename)){
      cleanup_task(task);
      continue;
    }
    task->func(*task, new_queue);
  }

  if(*quit_now){
    /* we might be in the middle of the queue, so clean up any
       remaining tasks in the current queue */
    for(; i < (*queue)->length; i++){
      cleanup_task(&((*queue)->tasks[i]));
    }
    free_queue(*queue);
    *queue = new_queue;
    new_queue = NULL;
    return false;
  }
  free_queue(*queue);
  *queue = new_queue;
  new_queue = NULL;

  return true;
}

/* End of regular code section */

/* Start of tests section; here are the tests for the above code */

/* This "fixture" data structure is used by the test setup and
   teardown functions */
typedef struct {
  struct sigaction orig_sigaction;
  sigset_t orig_sigmask;
} test_fixture;

static void test_setup(test_fixture *fixture,
		       __attribute__((unused))
		       gconstpointer user_data){
  g_assert_true(setup_signal_handler(&fixture->orig_sigaction));
  g_assert_true(block_sigchld(&fixture->orig_sigmask));
}

static void test_teardown(test_fixture *fixture,
			  __attribute__((unused))
			  gconstpointer user_data){
  g_assert_true(restore_signal_handler(&fixture->orig_sigaction));
  g_assert_true(restore_sigmask(&fixture->orig_sigmask));
}

/* Utility function used by tests to search queue for matching task */
__attribute__((pure, nonnull, warn_unused_result))
static task_context *find_matching_task(const task_queue *const queue,
					const task_context task){
  /* The argument "task" structure is a pattern to match; 0 in any
     member means any value matches, otherwise the value must match.
     The filename strings are compared by strcmp(), not by pointer. */
  for(size_t i = 0; i < queue->length; i++){
    task_context *const current_task = queue->tasks+i;
    /* Check all members of task_context, if set to a non-zero value.
       If a member does not match, continue to next task in queue */

    /* task_func *const func */
    if(task.func != NULL and current_task->func != task.func){
      continue;
    }
    /* char *const question_filename; */
    if(task.question_filename != NULL
       and (current_task->question_filename == NULL
	    or strcmp(current_task->question_filename,
		      task.question_filename) != 0)){
      continue;
    }
    /* const pid_t pid; */
    if(task.pid != 0 and current_task->pid != task.pid){
      continue;
    }
    /* const int epoll_fd; */
    if(task.epoll_fd != 0
       and current_task->epoll_fd != task.epoll_fd){
      continue;
    }
    /* bool *const quit_now; */
    if(task.quit_now != NULL
       and current_task->quit_now != task.quit_now){
      continue;
    }
    /* const int fd; */
    if(task.fd != 0 and current_task->fd != task.fd){
      continue;
    }
    /* bool *const mandos_client_exited; */
    if(task.mandos_client_exited != NULL
       and current_task->mandos_client_exited
       != task.mandos_client_exited){
      continue;
    }
    /* buffer *const password; */
    if(task.password != NULL
       and current_task->password != task.password){
      continue;
    }
    /* bool *const password_is_read; */
    if(task.password_is_read != NULL
       and current_task->password_is_read != task.password_is_read){
      continue;
    }
    /* char *filename; */
    if(task.filename != NULL
       and (current_task->filename == NULL
	    or strcmp(current_task->filename, task.filename) != 0)){
      continue;
    }
    /* string_set *const cancelled_filenames; */
    if(task.cancelled_filenames != NULL
       and current_task->cancelled_filenames
       != task.cancelled_filenames){
      continue;
    }
    /* const mono_microsecs notafter; */
    if(task.notafter != 0
       and current_task->notafter != task.notafter){
      continue;
    }
    /* const mono_microsecs *const current_time; */
    if(task.current_time != NULL
       and current_task->current_time != task.current_time){
      continue;
    }
    /* Current task matches all members; return it */
    return current_task;
  }
  /* No task in queue matches passed pattern task */
  return NULL;
}

static void test_create_queue(__attribute__((unused))
			      test_fixture *fixture,
			      __attribute__((unused))
			      gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *const queue = create_queue();
  g_assert_nonnull(queue);
  g_assert_null(queue->tasks);
  g_assert_true(queue->length == 0);
  g_assert_true(queue->next_run == 0);
}

static task_func dummy_func;

static void test_add_to_queue(__attribute__((unused))
			      test_fixture *fixture,
			      __attribute__((unused))
			      gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  g_assert_true(add_to_queue(queue,
			     (task_context){ .func=dummy_func }));
  g_assert_true(queue->length == 1);
  g_assert_nonnull(queue->tasks);
  g_assert_true(queue->tasks[0].func == dummy_func);
}

static void dummy_func(__attribute__((unused))
		       const task_context task,
		       __attribute__((unused))
		       task_queue *const queue){
}

static void test_queue_has_question_empty(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  g_assert_false(queue_has_question(queue));
}

static void test_queue_has_question_false(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  g_assert_true(add_to_queue(queue,
			     (task_context){ .func=dummy_func }));
  g_assert_false(queue_has_question(queue));
}

static void test_queue_has_question_true(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  char *const question_filename
    = strdup("/nonexistent/question_filename");
  g_assert_nonnull(question_filename);
  task_context task = {
    .func=dummy_func,
    .question_filename=question_filename,
  };
  g_assert_true(add_to_queue(queue, task));
  g_assert_true(queue_has_question(queue));
}

static void test_queue_has_question_false2(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  task_context task = { .func=dummy_func };
  g_assert_true(add_to_queue(queue, task));
  g_assert_true(add_to_queue(queue, task));
  g_assert_cmpint((int)queue->length, ==, 2);
  g_assert_false(queue_has_question(queue));
}

static void test_queue_has_question_true2(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  task_context task1 = { .func=dummy_func };
  g_assert_true(add_to_queue(queue, task1));
  char *const question_filename
    = strdup("/nonexistent/question_filename");
  g_assert_nonnull(question_filename);
  task_context task2 = {
    .func=dummy_func,
    .question_filename=question_filename,
  };
  g_assert_true(add_to_queue(queue, task2));
  g_assert_cmpint((int)queue->length, ==, 2);
  g_assert_true(queue_has_question(queue));
}

static void test_cleanup_buffer(__attribute__((unused))
				test_fixture *fixture,
				__attribute__((unused))
				gconstpointer user_data){
  buffer buf = {};

  const size_t buffersize = 10;

  buf.data = malloc(buffersize);
  g_assert_nonnull(buf.data);
  if(mlock(buf.data, buffersize) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }

  cleanup_buffer(&buf);
  g_assert_null(buf.data);
}

static
void test_string_set_new_set_contains_nothing(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set = {};
  g_assert_false(string_set_contains(set, "")); /* Empty string */
  g_assert_false(string_set_contains(set, "test_string"));
}

static void
test_string_set_with_added_string_contains_it(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set = {};
  g_assert_true(string_set_add(&set, "test_string"));
  g_assert_true(string_set_contains(set, "test_string"));
}

static void
test_string_set_cleared_does_not_contain_str(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set = {};
  g_assert_true(string_set_add(&set, "test_string"));
  string_set_clear(&set);
  g_assert_false(string_set_contains(set, "test_string"));
}

static
void test_string_set_swap_one_with_empty(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set1 = {};
  __attribute__((cleanup(string_set_clear)))
    string_set set2 = {};
  g_assert_true(string_set_add(&set1, "test_string1"));
  string_set_swap(&set1, &set2);
  g_assert_false(string_set_contains(set1, "test_string1"));
  g_assert_true(string_set_contains(set2, "test_string1"));
}

static
void test_string_set_swap_empty_with_one(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set1 = {};
  __attribute__((cleanup(string_set_clear)))
    string_set set2 = {};
  g_assert_true(string_set_add(&set2, "test_string2"));
  string_set_swap(&set1, &set2);
  g_assert_true(string_set_contains(set1, "test_string2"));
  g_assert_false(string_set_contains(set2, "test_string2"));
}

static void test_string_set_swap_one_with_one(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(string_set_clear)))
    string_set set1 = {};
  __attribute__((cleanup(string_set_clear)))
    string_set set2 = {};
  g_assert_true(string_set_add(&set1, "test_string1"));
  g_assert_true(string_set_add(&set2, "test_string2"));
  string_set_swap(&set1, &set2);
  g_assert_false(string_set_contains(set1, "test_string1"));
  g_assert_true(string_set_contains(set1, "test_string2"));
  g_assert_false(string_set_contains(set2, "test_string2"));
  g_assert_true(string_set_contains(set2, "test_string1"));
}

static bool fd_has_cloexec_and_nonblock(const int);

static bool epoll_set_contains(int, int, uint32_t);

static void test_start_mandos_client(test_fixture *fixture,
				     __attribute__((unused))
				     gconstpointer user_data){

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/bin/true", NULL };

  g_assert_true(start_mandos_client(queue, epoll_fd,
				    &mandos_client_exited, &quit_now,
				    &password, &password_is_read,
				    &fixture->orig_sigaction,
				    fixture->orig_sigmask,
				    helper_directory, 0, 0, argv));

  g_assert_cmpuint((unsigned int)queue->length, >=, 2);

  const task_context *const added_wait_task
    = find_matching_task(queue, (task_context){
	.func=wait_for_mandos_client_exit,
	.mandos_client_exited=&mandos_client_exited,
	.quit_now=&quit_now,
      });
  g_assert_nonnull(added_wait_task);
  g_assert_cmpint(added_wait_task->pid, >, 0);
  g_assert_cmpint(kill(added_wait_task->pid, SIGKILL), ==, 0);
  waitpid(added_wait_task->pid, NULL, 0);

  const task_context *const added_read_task
    = find_matching_task(queue, (task_context){
	.func=read_mandos_client_output,
	.epoll_fd=epoll_fd,
	.password=&password,
	.password_is_read=&password_is_read,
	.quit_now=&quit_now,
      });
  g_assert_nonnull(added_read_task);
  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));
  g_assert_true(epoll_set_contains(epoll_fd, added_read_task->fd,
				   EPOLLIN | EPOLLRDHUP));
}

static bool fd_has_cloexec_and_nonblock(const int fd){
  const int socket_fd_flags = fcntl(fd, F_GETFD, 0);
  const int socket_file_flags = fcntl(fd, F_GETFL, 0);
  return ((socket_fd_flags >= 0)
	  and (socket_fd_flags & FD_CLOEXEC)
	  and (socket_file_flags >= 0)
	  and (socket_file_flags & O_NONBLOCK));
}

__attribute__((const))
bool is_privileged(void){
  uid_t user = getuid() + 1;
  if(user == 0){		/* Overflow check */
    user++;
  }
  gid_t group = getuid() + 1;
  if(group == 0){		/* Overflow check */
    group++;
  }
  const pid_t pid = fork();
  if(pid == 0){			/* Child */
    if(setresgid((uid_t)-1, group, group) == -1){
      if(errno != EPERM){
	error(EXIT_FAILURE, errno, "Failed to setresgid(-1, %" PRIuMAX
	      ", %" PRIuMAX")", (uintmax_t)group, (uintmax_t)group);
      }
      exit(EXIT_FAILURE);
    }
    if(setresuid((uid_t)-1, user, user) == -1){
      if(errno != EPERM){
	error(EXIT_FAILURE, errno, "Failed to setresuid(-1, %" PRIuMAX
	      ", %" PRIuMAX")", (uintmax_t)user, (uintmax_t)user);
      }
      exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
  }
  int status;
  waitpid(pid, &status, 0);
  if(WIFEXITED(status) and (WEXITSTATUS(status) == EXIT_SUCCESS)){
    return true;
  }
  return false;
}

static bool epoll_set_contains(int epoll_fd, int fd, uint32_t events){
  /* Only scan for events in this eventmask */
  const uint32_t eventmask = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
  __attribute__((cleanup(cleanup_string)))
    char *fdinfo_name = NULL;
  int ret = asprintf(&fdinfo_name, "/proc/self/fdinfo/%d", epoll_fd);
  g_assert_cmpint(ret, >, 0);
  g_assert_nonnull(fdinfo_name);

  FILE *fdinfo = fopen(fdinfo_name, "r");
  g_assert_nonnull(fdinfo);
  uint32_t reported_events;
  buffer line = {};
  int found_fd = -1;

  do {
    if(getline(&line.data, &line.allocated, fdinfo) < 0){
      break;
    }
    /* See proc(5) for format of /proc/PID/fdinfo/FD for epoll fd's */
    if(sscanf(line.data, "tfd: %d events: %" SCNx32 " ",
	      &found_fd, &reported_events) == 2){
      if(found_fd == fd){
	break;
      }
    }
  } while(not feof(fdinfo) and not ferror(fdinfo));
  g_assert_cmpint(fclose(fdinfo), ==, 0);
  free(line.data);
  if(found_fd != fd){
    return false;
  }

  if(events == 0){
    /* Don't check events if none are given */
    return true;
  }
  return (reported_events & eventmask) == (events & eventmask);
}

static void test_start_mandos_client_execv(test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  const char helper_directory[] = "/nonexistent";
  /* Can't execv("/", ...), so this should fail */
  const char *const argv[] = { "/", NULL };

  {
    __attribute__((cleanup(cleanup_close)))
      const int devnull_fd = open("/dev/null",
				  O_WRONLY | O_CLOEXEC | O_NOCTTY);
    g_assert_cmpint(devnull_fd, >=, 0);
    __attribute__((cleanup(cleanup_close)))
      const int real_stderr_fd = dup(STDERR_FILENO);
    g_assert_cmpint(real_stderr_fd, >=, 0);
    dup2(devnull_fd, STDERR_FILENO);

    const bool success = start_mandos_client(queue, epoll_fd,
					     &mandos_client_exited,
					     &quit_now,
					     &password,
					     (bool[]){false},
					     &fixture->orig_sigaction,
					     fixture->orig_sigmask,
					     helper_directory, 0, 0,
					     argv);
    dup2(real_stderr_fd, STDERR_FILENO);
    g_assert_true(success);
  }
  g_assert_cmpuint((unsigned int)queue->length, ==, 2);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};

    {
      __attribute__((cleanup(cleanup_close)))
	const int devnull_fd = open("/dev/null",
				    O_WRONLY | O_CLOEXEC | O_NOCTTY);
      g_assert_cmpint(devnull_fd, >=, 0);
      __attribute__((cleanup(cleanup_close)))
	const int real_stderr_fd = dup(STDERR_FILENO);
      g_assert_cmpint(real_stderr_fd, >=, 0);
      g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
      dup2(devnull_fd, STDERR_FILENO);
      const bool success = run_queue(&queue, &cancelled_filenames,
				     &quit_now);
      dup2(real_stderr_fd, STDERR_FILENO);
      if(not success){
	break;
      }
    }
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_true(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);
}

static void test_start_mandos_client_suid_euid(test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  if(not is_privileged()){
    g_test_skip("Not privileged");
    return;
  }

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/usr/bin/id", "--user", NULL };
  uid_t user = 1000;
  gid_t group = 1001;

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, user,
					   group, argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_nonnull(password.data);

  uintmax_t id;
  g_assert_cmpint(sscanf(password.data, "%" SCNuMAX "\n", &id),
		  ==, 1);
  g_assert_true((uid_t)id == id);

  g_assert_cmpuint((unsigned int)id, ==, 0);
}

static void test_start_mandos_client_suid_egid(test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  if(not is_privileged()){
    g_test_skip("Not privileged");
    return;
  }

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/usr/bin/id", "--group", NULL };
  uid_t user = 1000;
  gid_t group = 1001;

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, user,
					   group, argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_nonnull(password.data);

  uintmax_t id;
  g_assert_cmpint(sscanf(password.data, "%" SCNuMAX "\n", &id),
		  ==, 1);
  g_assert_true((gid_t)id == id);

  g_assert_cmpuint((unsigned int)id, ==, 0);
}

static void test_start_mandos_client_suid_ruid(test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  if(not is_privileged()){
    g_test_skip("Not privileged");
    return;
  }

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/usr/bin/id", "--user", "--real",
    NULL };
  uid_t user = 1000;
  gid_t group = 1001;

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, user,
					   group, argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_nonnull(password.data);

  uintmax_t id;
  g_assert_cmpint(sscanf(password.data, "%" SCNuMAX "\n", &id),
		  ==, 1);
  g_assert_true((uid_t)id == id);

  g_assert_cmpuint((unsigned int)id, ==, user);
}

static void test_start_mandos_client_suid_rgid(test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  if(not is_privileged()){
    g_test_skip("Not privileged");
    return;
  }

  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/usr/bin/id", "--group", "--real",
    NULL };
  uid_t user = 1000;
  gid_t group = 1001;

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, user,
					   group, argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_nonnull(password.data);

  uintmax_t id;
  g_assert_cmpint(sscanf(password.data, "%" SCNuMAX "\n", &id),
		  ==, 1);
  g_assert_true((gid_t)id == id);

  g_assert_cmpuint((unsigned int)id, ==, group);
}

static void test_start_mandos_client_read(test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char dummy_test_password[] = "dummy test password";
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/bin/echo", "-n", dummy_test_password,
    NULL };

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, 0, 0,
					   argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_cmpint((int)password.length, ==,
		  sizeof(dummy_test_password)-1);
  g_assert_nonnull(password.data);
  g_assert_cmpint(memcmp(dummy_test_password, password.data,
			 sizeof(dummy_test_password)-1), ==, 0);
}

static
void test_start_mandos_client_helper_directory(test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  const char *const argv[] = { "/bin/sh", "-c",
    "echo -n ${MANDOSPLUGINHELPERDIR}", NULL };

  const bool success = start_mandos_client(queue, epoll_fd,
					   &mandos_client_exited,
					   &quit_now, &password,
					   &password_is_read,
					   &fixture->orig_sigaction,
					   fixture->orig_sigmask,
					   helper_directory, 0, 0,
					   argv);
  g_assert_true(success);
  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while(((queue->length) > 0)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(mandos_client_exited);

  g_assert_true(password_is_read);
  g_assert_cmpint((int)password.length, ==,
		  sizeof(helper_directory)-1);
  g_assert_nonnull(password.data);
  g_assert_cmpint(memcmp(helper_directory, password.data,
			 sizeof(helper_directory)-1), ==, 0);
}

__attribute__((nonnull, warn_unused_result))
static bool proc_status_sigblk_to_sigset(const char *const,
					 sigset_t *const);

static void test_start_mandos_client_sigmask(test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  bool password_is_read = false;
  const char helper_directory[] = "/nonexistent";
  /* see proc(5) for format of /proc/self/status */
  const char *const argv[] = { "/usr/bin/awk",
    "$1==\"SigBlk:\"{ print $2 }", "/proc/self/status", NULL };

  g_assert_true(start_mandos_client(queue, epoll_fd,
				    &mandos_client_exited, &quit_now,
				    &password, &password_is_read,
				    &fixture->orig_sigaction,
				    fixture->orig_sigmask,
				    helper_directory, 0, 0, argv));

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    queue->next_run = 0;
    string_set cancelled_filenames = {};
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while((not (mandos_client_exited and password_is_read))
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));
  g_assert_true(mandos_client_exited);
  g_assert_true(password_is_read);

  sigset_t parsed_sigmask;
  g_assert_true(proc_status_sigblk_to_sigset(password.data,
					     &parsed_sigmask));

  for(int signum = 1; signum < NSIG; signum++){
    const bool has_signal = sigismember(&parsed_sigmask, signum);
    if(sigismember(&fixture->orig_sigmask, signum)){
      g_assert_true(has_signal);
    } else {
      g_assert_false(has_signal);
    }
  }
}

__attribute__((nonnull, warn_unused_result))
static bool proc_status_sigblk_to_sigset(const char *const sigblk,
					 sigset_t *const sigmask){
  /* parse /proc/PID/status SigBlk value and convert to a sigset_t */
  uintmax_t scanned_sigmask;
  if(sscanf(sigblk, "%" SCNxMAX " ", &scanned_sigmask) != 1){
    return false;
  }
  if(sigemptyset(sigmask) != 0){
    return false;
  }
  for(int signum = 1; signum < NSIG; signum++){
    if(scanned_sigmask & ((uintmax_t)1 << (signum-1))){
      if(sigaddset(sigmask, signum) != 0){
	return false;
      }
    }
  }
  return true;
}

static void run_task_with_stderr_to_dev_null(const task_context task,
					     task_queue *const queue);

static
void test_wait_for_mandos_client_exit_badpid(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){

  bool mandos_client_exited = false;
  bool quit_now = false;

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const task_context task = {
    .func=wait_for_mandos_client_exit,
    .pid=1,
    .mandos_client_exited=&mandos_client_exited,
    .quit_now=&quit_now,
  };
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_false(mandos_client_exited);
  g_assert_true(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static void run_task_with_stderr_to_dev_null(const task_context task,
					     task_queue *const queue){
  FILE *real_stderr = stderr;
  FILE *devnull = fopen("/dev/null", "we");
  g_assert_nonnull(devnull);

  stderr = devnull;
  task.func(task, queue);
  stderr = real_stderr;

  g_assert_cmpint(fclose(devnull), ==, 0);
}

static
void test_wait_for_mandos_client_exit_noexit(test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;

  pid_t create_eternal_process(void){
    const pid_t pid = fork();
    if(pid == 0){		/* Child */
      if(not restore_signal_handler(&fixture->orig_sigaction)){
	_exit(EXIT_FAILURE);
      }
      if(not restore_sigmask(&fixture->orig_sigmask)){
	_exit(EXIT_FAILURE);
      }
      while(true){
	pause();
      }
    }
    return pid;
  }
  pid_t pid = create_eternal_process();
  g_assert_true(pid != -1);

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const task_context task = {
    .func=wait_for_mandos_client_exit,
    .pid=pid,
    .mandos_client_exited=&mandos_client_exited,
    .quit_now=&quit_now,
  };
  task.func(task, queue);

  g_assert_false(mandos_client_exited);
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=wait_for_mandos_client_exit,
	.pid=task.pid,
	.mandos_client_exited=&mandos_client_exited,
	.quit_now=&quit_now,
      }));
}

static
void test_wait_for_mandos_client_exit_success(test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;

  pid_t create_successful_process(void){
    const pid_t pid = fork();
    if(pid == 0){		/* Child */
      if(not restore_signal_handler(&fixture->orig_sigaction)){
	_exit(EXIT_FAILURE);
      }
      if(not restore_sigmask(&fixture->orig_sigmask)){
	_exit(EXIT_FAILURE);
      }
      exit(EXIT_SUCCESS);
    }
    return pid;
  }
  const pid_t pid = create_successful_process();
  g_assert_true(pid != -1);

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const task_context initial_task = {
    .func=wait_for_mandos_client_exit,
    .pid=pid,
    .mandos_client_exited=&mandos_client_exited,
    .quit_now=&quit_now,
  };
  g_assert_true(add_to_queue(queue, initial_task));

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  do {
    queue->next_run = 0;
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    g_assert_true(run_queue(&queue, (string_set[]){{}}, &quit_now));
    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while((not mandos_client_exited)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_true(mandos_client_exited);
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static
void test_wait_for_mandos_client_exit_failure(test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;

  pid_t create_failing_process(void){
    const pid_t pid = fork();
    if(pid == 0){		/* Child */
      if(not restore_signal_handler(&fixture->orig_sigaction)){
	_exit(EXIT_FAILURE);
      }
      if(not restore_sigmask(&fixture->orig_sigmask)){
	_exit(EXIT_FAILURE);
      }
      exit(EXIT_FAILURE);
    }
    return pid;
  }
  const pid_t pid = create_failing_process();
  g_assert_true(pid != -1);

  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  g_assert_true(add_to_queue(queue, (task_context){
	.func=wait_for_mandos_client_exit,
	.pid=pid,
	.mandos_client_exited=&mandos_client_exited,
	.quit_now=&quit_now,
      }));

  g_assert_true(sigismember(&fixture->orig_sigmask, SIGCHLD) == 0);

  __attribute__((cleanup(cleanup_close)))
    const int devnull_fd = open("/dev/null",
				O_WRONLY | O_CLOEXEC | O_NOCTTY);
  g_assert_cmpint(devnull_fd, >=, 0);
  __attribute__((cleanup(cleanup_close)))
    const int real_stderr_fd = dup(STDERR_FILENO);
  g_assert_cmpint(real_stderr_fd, >=, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    dup2(devnull_fd, STDERR_FILENO);
    const bool success = run_queue(&queue, &cancelled_filenames,
				   &quit_now);
    dup2(real_stderr_fd, STDERR_FILENO);
    if(not success){
      break;
    }

    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while((not mandos_client_exited)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_true(quit_now);
  g_assert_true(mandos_client_exited);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static
void test_wait_for_mandos_client_exit_killed(test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  bool mandos_client_exited = false;
  bool quit_now = false;

  pid_t create_killed_process(void){
    const pid_t pid = fork();
    if(pid == 0){		/* Child */
      if(not restore_signal_handler(&fixture->orig_sigaction)){
	_exit(EXIT_FAILURE);
      }
      if(not restore_sigmask(&fixture->orig_sigmask)){
	_exit(EXIT_FAILURE);
      }
      while(true){
	pause();
      }
    }
    kill(pid, SIGKILL);
    return pid;
  }
  const pid_t pid = create_killed_process();
  g_assert_true(pid != -1);

  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  g_assert_true(add_to_queue(queue, (task_context){
	.func=wait_for_mandos_client_exit,
	.pid=pid,
	.mandos_client_exited=&mandos_client_exited,
	.quit_now=&quit_now,
      }));

  __attribute__((cleanup(cleanup_close)))
    const int devnull_fd = open("/dev/null",
				O_WRONLY | O_CLOEXEC, O_NOCTTY);
  g_assert_cmpint(devnull_fd, >=, 0);
  __attribute__((cleanup(cleanup_close)))
    const int real_stderr_fd = dup(STDERR_FILENO);
  g_assert_cmpint(real_stderr_fd, >=, 0);

  struct timespec starttime, currtime;
  g_assert_true(clock_gettime(CLOCK_MONOTONIC, &starttime) == 0);
  do {
    g_assert_true(wait_for_event(epoll_fd, queue->next_run, 0));
    dup2(devnull_fd, STDERR_FILENO);
    const bool success = run_queue(&queue, &cancelled_filenames,
				   &quit_now);
    dup2(real_stderr_fd, STDERR_FILENO);
    if(not success){
      break;
    }

    g_assert_true(clock_gettime(CLOCK_MONOTONIC, &currtime) == 0);
  } while((not mandos_client_exited)
	  and (not quit_now)
	  and ((currtime.tv_sec - starttime.tv_sec) < 10));

  g_assert_true(mandos_client_exited);
  g_assert_true(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static bool epoll_set_does_not_contain(int, int);

static
void test_read_mandos_client_output_readerror(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  /* Reading /proc/self/mem from offset 0 will always give EIO */
  const int fd = open("/proc/self/mem",
		      O_RDONLY | O_CLOEXEC | O_NOCTTY);

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=fd,
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_false(password_is_read);
  g_assert_cmpint((int)password.length, ==, 0);
  g_assert_true(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_true(epoll_set_does_not_contain(epoll_fd, fd));

  g_assert_cmpint(close(fd), ==, -1);
}

static bool epoll_set_does_not_contain(int epoll_fd, int fd){
  return not epoll_set_contains(epoll_fd, fd, 0);
}

static
void test_read_mandos_client_output_nodata(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  task.func(task, queue);
  g_assert_false(password_is_read);
  g_assert_cmpint((int)password.length, ==, 0);
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_mandos_client_output,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.password=&password,
	.password_is_read=&password_is_read,
	.quit_now=&quit_now,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpint(close(pipefds[1]), ==, 0);
}

static void test_read_mandos_client_output_eof(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  task.func(task, queue);
  g_assert_true(password_is_read);
  g_assert_cmpint((int)password.length, ==, 0);
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_true(epoll_set_does_not_contain(epoll_fd, pipefds[0]));

  g_assert_cmpint(close(pipefds[0]), ==, -1);
}

static
void test_read_mandos_client_output_once(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  const char dummy_test_password[] = "dummy test password";
  /* Start with a pre-allocated buffer */
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(sizeof(dummy_test_password)),
    .length=0,
    .allocated=sizeof(dummy_test_password),
  };
  g_assert_nonnull(password.data);
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  g_assert_true(sizeof(dummy_test_password) <= PIPE_BUF);
  g_assert_cmpint((int)write(pipefds[1], dummy_test_password,
			     sizeof(dummy_test_password)),
		  ==, (int)sizeof(dummy_test_password));

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  task.func(task, queue);

  g_assert_false(password_is_read);
  g_assert_cmpint((int)password.length, ==,
		  (int)sizeof(dummy_test_password));
  g_assert_nonnull(password.data);
  g_assert_cmpint(memcmp(password.data, dummy_test_password,
			 sizeof(dummy_test_password)), ==, 0);

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_mandos_client_output,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.password=&password,
	.password_is_read=&password_is_read,
	.quit_now=&quit_now,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpint(close(pipefds[1]), ==, 0);
}

static
void test_read_mandos_client_output_malloc(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  const char dummy_test_password[] = "dummy test password";
  /* Start with an empty buffer */
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  g_assert_true(sizeof(dummy_test_password) <= PIPE_BUF);
  g_assert_cmpint((int)write(pipefds[1], dummy_test_password,
			     sizeof(dummy_test_password)),
		  ==, (int)sizeof(dummy_test_password));

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  task.func(task, queue);

  g_assert_false(password_is_read);
  g_assert_cmpint((int)password.length, ==,
		  (int)sizeof(dummy_test_password));
  g_assert_nonnull(password.data);
  g_assert_cmpint(memcmp(password.data, dummy_test_password,
			 sizeof(dummy_test_password)), ==, 0);

  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_mandos_client_output,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.password=&password,
	.password_is_read=&password_is_read,
	.quit_now=&quit_now,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpint(close(pipefds[1]), ==, 0);
}

static
void test_read_mandos_client_output_append(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  const char dummy_test_password[] = "dummy test password";
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(PIPE_BUF),
    .length=PIPE_BUF,
    .allocated=PIPE_BUF,
  };
  g_assert_nonnull(password.data);
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }

  memset(password.data, 'x', PIPE_BUF);
  char password_expected[PIPE_BUF];
  memcpy(password_expected, password.data, PIPE_BUF);

  bool password_is_read = false;
  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  g_assert_true(sizeof(dummy_test_password) <= PIPE_BUF);
  g_assert_cmpint((int)write(pipefds[1], dummy_test_password,
			     sizeof(dummy_test_password)),
		  ==, (int)sizeof(dummy_test_password));

  task_context task = {
    .func=read_mandos_client_output,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .password=&password,
    .password_is_read=&password_is_read,
    .quit_now=&quit_now,
  };
  task.func(task, queue);

  g_assert_false(password_is_read);
  g_assert_cmpint((int)password.length, ==,
		  PIPE_BUF + sizeof(dummy_test_password));
  g_assert_nonnull(password.data);
  g_assert_cmpint(memcmp(password_expected, password.data, PIPE_BUF),
		  ==, 0);
  g_assert_cmpint(memcmp(password.data + PIPE_BUF,
			 dummy_test_password,
			 sizeof(dummy_test_password)), ==, 0);
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_mandos_client_output,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.password=&password,
	.password_is_read=&password_is_read,
	.quit_now=&quit_now,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));
}

static char *make_temporary_directory(void);

static void test_add_inotify_dir_watch(__attribute__((unused))
				       test_fixture *fixture,
				       __attribute__((unused))
				       gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.quit_now=&quit_now,
	.password=&password,
	.filename=tempdir,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));
  g_assert_true(epoll_set_contains(added_read_task->epoll_fd,
				   added_read_task->fd,
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static char *make_temporary_directory(void){
  char *name = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(name);
  char *result = mkdtemp(name);
  if(result == NULL){
    free(name);
  }
  return result;
}

static void test_add_inotify_dir_watch_fail(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  const char nonexistent_dir[] = "/nonexistent";

  FILE *real_stderr = stderr;
  FILE *devnull = fopen("/dev/null", "we");
  g_assert_nonnull(devnull);
  stderr = devnull;
  g_assert_false(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				       &password, nonexistent_dir,
				       &cancelled_filenames,
				       &current_time,
				       &mandos_client_exited,
				       &password_is_read));
  stderr = real_stderr;
  g_assert_cmpint(fclose(devnull), ==, 0);

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static void test_add_inotify_dir_watch_nondir(__attribute__((unused))
					      test_fixture *fixture,
					    __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  const char not_a_directory[] = "/dev/tty";

  FILE *real_stderr = stderr;
  FILE *devnull = fopen("/dev/null", "we");
  g_assert_nonnull(devnull);
  stderr = devnull;
  g_assert_false(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				       &password, not_a_directory,
				       &cancelled_filenames,
				       &current_time,
				       &mandos_client_exited,
				       &password_is_read));
  stderr = real_stderr;
  g_assert_cmpint(fclose(devnull), ==, 0);

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static void test_add_inotify_dir_watch_EAGAIN(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  g_assert_cmpint(read(added_read_task->fd, ievent, ievent_size), ==,
		  -1);
  g_assert_cmpint(errno, ==, EAGAIN);

  free(ievent);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static char *make_temporary_file_in_directory(const char
					      *const dir);

static
void test_add_inotify_dir_watch_IN_CLOSE_WRITE(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));

  __attribute__((cleanup(cleanup_string)))
    char *filename = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(filename);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  ssize_t read_size = 0;
  read_size = read(added_read_task->fd, ievent, ievent_size);

  g_assert_cmpint((int)read_size, >, 0);
  g_assert_true(ievent->mask & IN_CLOSE_WRITE);
  g_assert_cmpstr(ievent->name, ==, basename(filename));

  free(ievent);

  g_assert_cmpint(unlink(filename), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static char *make_temporary_prefixed_file_in_directory(const char
						       *const prefix,
						       const char
						       *const dir){
  char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%sXXXXXX", dir, prefix),
		  >, 0);
  g_assert_nonnull(filename);
  const int fd = mkostemp(filename, O_CLOEXEC);
  g_assert_cmpint(fd, >=, 0);
  g_assert_cmpint(close(fd), ==, 0);
  return filename;
}

static char *make_temporary_file_in_directory(const char
					      *const dir){
  return make_temporary_prefixed_file_in_directory("temp", dir);
}

static
void test_add_inotify_dir_watch_IN_MOVED_TO(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *watchdir = make_temporary_directory();
  g_assert_nonnull(watchdir);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, watchdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));

  char *sourcedir = make_temporary_directory();
  g_assert_nonnull(sourcedir);

  __attribute__((cleanup(cleanup_string)))
    char *filename = make_temporary_file_in_directory(sourcedir);
  g_assert_nonnull(filename);

  __attribute__((cleanup(cleanup_string)))
    char *targetfilename = NULL;
  g_assert_cmpint(asprintf(&targetfilename, "%s/%s", watchdir,
			   basename(filename)), >, 0);
  g_assert_nonnull(targetfilename);

  g_assert_cmpint(rename(filename, targetfilename), ==, 0);
  g_assert_cmpint(rmdir(sourcedir), ==, 0);
  free(sourcedir);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  ssize_t read_size = read(added_read_task->fd, ievent, ievent_size);

  g_assert_cmpint((int)read_size, >, 0);
  g_assert_true(ievent->mask & IN_MOVED_TO);
  g_assert_cmpstr(ievent->name, ==, basename(targetfilename));

  free(ievent);

  g_assert_cmpint(unlink(targetfilename), ==, 0);
  g_assert_cmpint(rmdir(watchdir), ==, 0);
}

static
void test_add_inotify_dir_watch_IN_MOVED_FROM(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(tempfilename);

  __attribute__((cleanup(cleanup_string)))
    char *targetdir = make_temporary_directory();
  g_assert_nonnull(targetdir);

  __attribute__((cleanup(cleanup_string)))
    char *targetfilename = NULL;
  g_assert_cmpint(asprintf(&targetfilename, "%s/%s", targetdir,
			   basename(tempfilename)), >, 0);
  g_assert_nonnull(targetfilename);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));

  g_assert_cmpint(rename(tempfilename, targetfilename), ==, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  ssize_t read_size = read(added_read_task->fd, ievent, ievent_size);

  g_assert_cmpint((int)read_size, >, 0);
  g_assert_true(ievent->mask & IN_MOVED_FROM);
  g_assert_cmpstr(ievent->name, ==, basename(tempfilename));

  free(ievent);

  g_assert_cmpint(unlink(targetfilename), ==, 0);
  g_assert_cmpint(rmdir(targetdir), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static
void test_add_inotify_dir_watch_IN_DELETE(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  __attribute__((cleanup(cleanup_string)))
    char *tempfile = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(tempfile);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));
  g_assert_cmpint(unlink(tempfile), ==, 0);

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  ssize_t read_size = 0;
  read_size = read(added_read_task->fd, ievent, ievent_size);

  g_assert_cmpint((int)read_size, >, 0);
  g_assert_true(ievent->mask & IN_DELETE);
  g_assert_cmpstr(ievent->name, ==, basename(tempfile));

  free(ievent);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static
void test_add_inotify_dir_watch_IN_EXCL_UNLINK(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  __attribute__((cleanup(cleanup_string)))
    char *tempfile = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(tempfile);
  int tempfile_fd = open(tempfile, O_WRONLY | O_CLOEXEC | O_NOCTTY
			 | O_NOFOLLOW);
  g_assert_cmpint(tempfile_fd, >, 2);

  g_assert_true(add_inotify_dir_watch(queue, epoll_fd, &quit_now,
				      &password, tempdir,
				      &cancelled_filenames,
				      &current_time,
				      &mandos_client_exited,
				      &password_is_read));
  g_assert_cmpint(unlink(tempfile), ==, 0);

  g_assert_cmpuint((unsigned int)queue->length, >, 0);

  const task_context *const added_read_task
    = find_matching_task(queue,
			 (task_context){ .func=read_inotify_event });
  g_assert_nonnull(added_read_task);

  g_assert_cmpint(added_read_task->fd, >, 2);
  g_assert_true(fd_has_cloexec_and_nonblock(added_read_task->fd));

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + NAME_MAX + 1);
  struct inotify_event *ievent = malloc(ievent_size);
  g_assert_nonnull(ievent);

  ssize_t read_size = 0;
  read_size = read(added_read_task->fd, ievent, ievent_size);

  g_assert_cmpint((int)read_size, >, 0);
  g_assert_true(ievent->mask & IN_DELETE);
  g_assert_cmpstr(ievent->name, ==, basename(tempfile));

  g_assert_cmpint(close(tempfile_fd), ==, 0);

  /* IN_EXCL_UNLINK should make the closing of the previously unlinked
     file not appear as an ievent, so we should not see it now. */
  read_size = read(added_read_task->fd, ievent, ievent_size);
  g_assert_cmpint((int)read_size, ==, -1);
  g_assert_true(errno == EAGAIN);

  free(ievent);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static void test_read_inotify_event_readerror(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  /* Reading /proc/self/mem from offset 0 will always result in EIO */
  const int fd = open("/proc/self/mem",
		      O_RDONLY | O_CLOEXEC | O_NOCTTY);

  bool quit_now = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=fd,
    .quit_now=&quit_now,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
  };
  g_assert_nonnull(task.filename);
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_true(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_true(epoll_set_does_not_contain(epoll_fd, fd));

  g_assert_cmpint(close(fd), ==, -1);
}

static void test_read_inotify_event_bad_epoll(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  const mono_microsecs current_time = 17;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  const int epoll_fd = pipefds[0]; /* This will obviously fail */

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  g_assert_nonnull(task.filename);
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_nonnull(find_matching_task(queue, task));
  g_assert_true(queue->next_run == 1000000 + current_time);

  g_assert_cmpint(close(pipefds[0]), ==, 0);
  g_assert_cmpint(close(pipefds[1]), ==, 0);
}

static void test_read_inotify_event_nodata(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  g_assert_nonnull(task.filename);
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpint(close(pipefds[1]), ==, 0);
}

static void test_read_inotify_event_eof(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_true(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_true(epoll_set_does_not_contain(epoll_fd, pipefds[0]));

  g_assert_cmpint(close(pipefds[0]), ==, -1);
}

static
void test_read_inotify_event_IN_CLOSE_WRITE(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ask.dummy_file_name";
  ievent->mask = IN_CLOSE_WRITE;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run != 0);
  g_assert_cmpuint((unsigned int)queue->length, >=, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpuint((unsigned int)queue->length, >=, 2);

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=open_and_parse_question,
	.epoll_fd=epoll_fd,
	.filename=filename,
	.question_filename=filename,
	.password=&password,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));
}

static
void test_read_inotify_event_IN_MOVED_TO(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ask.dummy_file_name";
  ievent->mask = IN_MOVED_TO;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run != 0);
  g_assert_cmpuint((unsigned int)queue->length, >=, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  g_assert_cmpuint((unsigned int)queue->length, >=, 2);

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=open_and_parse_question,
	.epoll_fd=epoll_fd,
	.filename=filename,
	.question_filename=filename,
	.password=&password,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));
}

static
void test_read_inotify_event_IN_MOVED_FROM(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ask.dummy_file_name";
  ievent->mask = IN_MOVED_FROM;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_true(string_set_contains(*task.cancelled_filenames,
				    filename));
}

static void test_read_inotify_event_IN_DELETE(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ask.dummy_file_name";
  ievent->mask = IN_DELETE;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_true(string_set_contains(*task.cancelled_filenames,
				    filename));
}

static void
test_read_inotify_event_IN_CLOSE_WRITE_badname(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ignored.dummy_file_name";
  ievent->mask = IN_CLOSE_WRITE;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));
}

static void
test_read_inotify_event_IN_MOVED_TO_badname(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ignored.dummy_file_name";
  ievent->mask = IN_MOVED_TO;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames = &(string_set){},
    .notafter=0,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=task.cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));
}

static void
test_read_inotify_event_IN_MOVED_FROM_badname(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ignored.dummy_file_name";
  ievent->mask = IN_MOVED_FROM;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_false(string_set_contains(cancelled_filenames, filename));
}

static
void test_read_inotify_event_IN_DELETE_badname(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;

  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);

  /* "sufficient to read at least one event." - inotify(7) */
  const size_t ievent_max_size = (sizeof(struct inotify_event)
				  + NAME_MAX + 1);
  g_assert_cmpint(ievent_max_size, <=, PIPE_BUF);
  struct {
    struct inotify_event event;
    char name_buffer[NAME_MAX + 1];
  } ievent_buffer;
  struct inotify_event *const ievent = &ievent_buffer.event;

  const char dummy_file_name[] = "ignored.dummy_file_name";
  ievent->mask = IN_DELETE;
  ievent->len = sizeof(dummy_file_name);
  memcpy(ievent->name, dummy_file_name, sizeof(dummy_file_name));
  const size_t ievent_size = (sizeof(struct inotify_event)
			      + sizeof(dummy_file_name));
  g_assert_cmpint(write(pipefds[1], (char *)ievent, ievent_size),
		  ==, ievent_size);
  g_assert_cmpint(close(pipefds[1]), ==, 0);

  bool quit_now = false;
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  task_context task = {
    .func=read_inotify_event,
    .epoll_fd=epoll_fd,
    .fd=pipefds[0],
    .quit_now=&quit_now,
    .password=&password,
    .filename=strdup("/nonexistent"),
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_false(quit_now);
  g_assert_true(queue->next_run == 0);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=read_inotify_event,
	.epoll_fd=epoll_fd,
	.fd=pipefds[0],
	.quit_now=&quit_now,
	.password=&password,
	.filename=task.filename,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(epoll_set_contains(epoll_fd, pipefds[0],
				   EPOLLIN | EPOLLRDHUP));

  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", task.filename,
			   dummy_file_name), >, 0);
  g_assert_nonnull(filename);
  g_assert_false(string_set_contains(cancelled_filenames, filename));
}

static
void test_open_and_parse_question_ENOENT(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  char *const filename = strdup("/nonexistent");
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static void test_open_and_parse_question_EIO(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const mono_microsecs current_time = 0;

  char *filename = strdup("/proc/self/mem");
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static void
test_open_and_parse_question_parse_error(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int tempfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(tempfile, >, 0);
  const char bad_data[] = "this is bad syntax\n";
  g_assert_cmpint(write(tempfile, bad_data, sizeof(bad_data)),
		  ==, sizeof(bad_data));
  g_assert_cmpint(close(tempfile), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
  };
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static
void test_open_and_parse_question_nosocket(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nPID=1\n"), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static
void test_open_and_parse_question_badsocket(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=\nPID=1\n"), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static
void test_open_and_parse_question_nopid(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\n"), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static
void test_open_and_parse_question_badpid(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\nPID=\n"),
		  >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=(mono_microsecs[]){0},
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static void
test_open_and_parse_question_noexist_pid(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const mono_microsecs current_time = 0;

  /* Find value of sysctl kernel.pid_max */
  uintmax_t pid_max = 0;
  FILE *sysctl_pid_max = fopen("/proc/sys/kernel/pid_max", "r");
  g_assert_nonnull(sysctl_pid_max);
  g_assert_cmpint(fscanf(sysctl_pid_max, "%" PRIuMAX, &pid_max),
		  ==, 1);
  g_assert_cmpint(fclose(sysctl_pid_max), ==, 0);

  pid_t nonexisting_pid = ((pid_t)pid_max)+1;
  g_assert_true(nonexisting_pid > 0); /* Overflow check */

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\nPID=%"
			  PRIuMAX"\n", (uintmax_t)nonexisting_pid),
		  >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const question_filename = strdup(tempfilename);
  g_assert_nonnull(question_filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=question_filename,
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=question_filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static void
test_open_and_parse_question_no_notafter(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const mono_microsecs current_time = 0;

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\nPID=%"
			  PRIuMAX "\n", (uintmax_t)getpid()), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  __attribute__((cleanup(cleanup_string)))
    char *socket_filename = strdup("/nonexistent");
  g_assert_nonnull(socket_filename);
  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=connect_question_socket,
	.question_filename=tempfilename,
	.filename=socket_filename,
	.epoll_fd=epoll_fd,
	.password=&password,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(queue->next_run != 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static void
test_open_and_parse_question_bad_notafter(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  const mono_microsecs current_time = 0;

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\nPID=%"
			  PRIuMAX "\nNotAfter=\n",
			  (uintmax_t)getpid()), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  run_task_with_stderr_to_dev_null(task, queue);
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  __attribute__((cleanup(cleanup_string)))
    char *socket_filename = strdup("/nonexistent");
  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=connect_question_socket,
	.question_filename=tempfilename,
	.filename=socket_filename,
	.epoll_fd=epoll_fd,
	.password=&password,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));
  g_assert_true(queue->next_run != 0);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static
void assert_open_and_parse_question_with_notafter(const mono_microsecs
						  current_time,
						  const mono_microsecs
						  notafter,
						  const mono_microsecs
						  next_queue_run){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  queue->next_run = next_queue_run;

  __attribute__((cleanup(cleanup_string)))
    char *tempfilename = strdup("/tmp/mandosXXXXXX");
  g_assert_nonnull(tempfilename);
  int questionfile = mkostemp(tempfilename, O_CLOEXEC);
  g_assert_cmpint(questionfile, >, 0);
  FILE *qf = fdopen(questionfile, "w");
  g_assert_cmpint(fprintf(qf, "[Ask]\nSocket=/nonexistent\nPID=%"
			  PRIuMAX "\nNotAfter=%" PRIuMAX "\n",
			  (uintmax_t)getpid(), notafter), >, 0);
  g_assert_cmpint(fclose(qf), ==, 0);

  char *const filename = strdup(tempfilename);
  g_assert_nonnull(filename);
  task_context task = {
    .func=open_and_parse_question,
    .question_filename=filename,
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
  };
  task.func(task, queue);

  if(queue->length >= 1){
    __attribute__((cleanup(cleanup_string)))
      char *socket_filename = strdup("/nonexistent");
    g_assert_nonnull(find_matching_task(queue, (task_context){
	  .func=connect_question_socket,
	  .filename=socket_filename,
	  .epoll_fd=epoll_fd,
	  .password=&password,
	  .current_time=&current_time,
	  .cancelled_filenames=&cancelled_filenames,
	  .mandos_client_exited=&mandos_client_exited,
	  .password_is_read=&password_is_read,
	}));
    g_assert_true(queue->next_run != 0);
  }

  if(notafter == 0){
    g_assert_cmpuint((unsigned int)queue->length, ==, 1);
  } else if(current_time >= notafter) {
    g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  } else {
    g_assert_nonnull(find_matching_task(queue, (task_context){
	  .func=cancel_old_question,
	  .question_filename=tempfilename,
	  .filename=tempfilename,
	  .notafter=notafter,
	  .cancelled_filenames=&cancelled_filenames,
	  .current_time=&current_time,
	}));
  }
  g_assert_true(queue->next_run == 1);

  g_assert_cmpint(unlink(tempfilename), ==, 0);
}

static void
test_open_and_parse_question_notafter_0(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(0, 0, 0);
}

static void
test_open_and_parse_question_notafter_1(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(0, 1, 0);
}

static void
test_open_and_parse_question_notafter_1_1(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(0, 1, 1);
}

static void
test_open_and_parse_question_notafter_1_2(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(0, 1, 2);
}

static void
test_open_and_parse_question_equal_notafter(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(1, 1, 0);
}

static void
test_open_and_parse_question_late_notafter(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* current_time, notafter, next_queue_run */
  assert_open_and_parse_question_with_notafter(2, 1, 0);
}

static void assert_cancel_old_question_param(const mono_microsecs
					     next_queue_run,
					     const mono_microsecs
					     notafter,
					     const mono_microsecs
					     current_time,
					     const mono_microsecs
					     next_set_to){
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  queue->next_run = next_queue_run;

  char *const question_filename = strdup("/nonexistent");
  g_assert_nonnull(question_filename);
  task_context task = {
    .func=cancel_old_question,
    .question_filename=question_filename,
    .filename=question_filename,
    .notafter=notafter,
    .cancelled_filenames=&cancelled_filenames,
    .current_time=&current_time,
  };
  task.func(task, queue);

  if(current_time >= notafter){
    g_assert_cmpuint((unsigned int)queue->length, ==, 0);
    g_assert_true(string_set_contains(cancelled_filenames,
				      "/nonexistent"));
  } else {
    g_assert_nonnull(find_matching_task(queue, (task_context){
	  .func=cancel_old_question,
	  .question_filename=question_filename,
	  .filename=question_filename,
	  .notafter=notafter,
	  .cancelled_filenames=&cancelled_filenames,
	  .current_time=&current_time,
	}));

    g_assert_false(string_set_contains(cancelled_filenames,
				       question_filename));
  }
  g_assert_cmpuint((unsigned int)queue->next_run, ==,
		   (unsigned int)next_set_to);
}

static void test_cancel_old_question_0_1_2(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* next_queue_run unset,
     cancellation should happen because time has come,
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(0, 1, 2, 0);
}

static void test_cancel_old_question_0_2_1(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* If next_queue_run is 0, meaning unset, and notafter is 2,
     and current_time is not yet notafter or greater,
     update value of next_queue_run to value of notafter */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(0, 2, 1, 2);
}

static void test_cancel_old_question_1_2_3(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* next_queue_run 1,
     cancellation should happen because time has come,
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(1, 2, 3, 1);
}

static void test_cancel_old_question_1_3_2(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* If next_queue_run is set,
     and current_time is not yet notafter or greater,
     and notafter is larger than next_queue_run
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(1, 3, 2, 1);
}

static void test_cancel_old_question_2_1_3(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* next_queue_run 2,
     cancellation should happen because time has come,
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(2, 1, 3, 2);
}

static void test_cancel_old_question_2_3_1(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* If next_queue_run is set,
     and current_time is not yet notafter or greater,
     and notafter is larger than next_queue_run
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(2, 3, 1, 2);
}

static void test_cancel_old_question_3_1_2(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* next_queue_run 3,
     cancellation should happen because time has come,
     next_queue_run should be unchanged */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(3, 1, 2, 3);
}

static void test_cancel_old_question_3_2_1(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  /* If next_queue_run is set,
     and current_time is not yet notafter or greater,
     and notafter is smaller than next_queue_run
     update value of next_queue_run to value of notafter */
  /* next_queue_run, notafter, current_time, next_set_to */
  assert_cancel_old_question_param(3, 2, 1, 2);
}

static void
test_connect_question_socket_name_too_long(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const char question_filename[] = "/nonexistent/question";
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  struct sockaddr_un unix_socket = { .sun_family=AF_LOCAL };
  char socket_name[sizeof(unix_socket.sun_path)];
  memset(socket_name, 'x', sizeof(socket_name));
  socket_name[sizeof(socket_name)-1] = '\0';
  char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", tempdir, socket_name),
		  >, 0);
  g_assert_nonnull(filename);

  task_context task = {
    .func=connect_question_socket,
    .question_filename=strdup(question_filename),
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
    .current_time=(mono_microsecs[]){0},
  };
  g_assert_nonnull(task.question_filename);
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_true(string_set_contains(cancelled_filenames,
				    question_filename));
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(queue->next_run == 0);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static
void test_connect_question_socket_connect_fail(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const char question_filename[] = "/nonexistent/question";
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 3;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  char socket_name[] = "nonexistent";
  char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", tempdir, socket_name),
		  >, 0);
  g_assert_nonnull(filename);

  task_context task = {
    .func=connect_question_socket,
    .question_filename=strdup(question_filename),
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=filename,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
    .current_time=&current_time,
  };
  g_assert_nonnull(task.question_filename);
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_nonnull(find_matching_task(queue, task));

  g_assert_false(string_set_contains(cancelled_filenames,
				     question_filename));
  g_assert_cmpuint((unsigned int)queue->length, ==, 1);
  g_assert_true(queue->next_run == 1000000 + current_time);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static
void test_connect_question_socket_bad_epoll(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = open("/dev/null",
			      O_WRONLY | O_CLOEXEC | O_NOCTTY);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 5;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_close)))
    const int sock_fd = socket(PF_LOCAL, SOCK_DGRAM
			       | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  g_assert_cmpint(sock_fd, >=, 0);
  struct sockaddr_un sock_name = { .sun_family=AF_LOCAL };
  const char socket_name[] = "socket_name";
  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", tempdir, socket_name),
		  >, 0);
  g_assert_nonnull(filename);
  g_assert_cmpint((int)strlen(filename), <,
		  (int)sizeof(sock_name.sun_path));
  strncpy(sock_name.sun_path, filename, sizeof(sock_name.sun_path));
  sock_name.sun_path[sizeof(sock_name.sun_path)-1] = '\0';
  g_assert_cmpint((int)bind(sock_fd, (struct sockaddr *)&sock_name,
			    (socklen_t)SUN_LEN(&sock_name)), >=, 0);
  task_context task = {
    .func=connect_question_socket,
    .question_filename=strdup(question_filename),
    .epoll_fd=epoll_fd,
    .password=(buffer[]){{}},
    .filename=strdup(filename),
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
    .current_time=&current_time,
  };
  g_assert_nonnull(task.question_filename);
  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);
  const task_context *const added_task
    = find_matching_task(queue, task);
  g_assert_nonnull(added_task);
  g_assert_true(queue->next_run == 1000000 + current_time);

  g_assert_cmpint(unlink(filename), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static
void test_connect_question_socket_usable(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool mandos_client_exited = false;
  bool password_is_read = false;
  const mono_microsecs current_time = 0;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_close)))
    const int sock_fd = socket(PF_LOCAL, SOCK_DGRAM
			       | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  g_assert_cmpint(sock_fd, >=, 0);
  struct sockaddr_un sock_name = { .sun_family=AF_LOCAL };
  const char socket_name[] = "socket_name";
  __attribute__((cleanup(cleanup_string)))
    char *filename = NULL;
  g_assert_cmpint(asprintf(&filename, "%s/%s", tempdir, socket_name),
		  >, 0);
  g_assert_nonnull(filename);
  g_assert_cmpint((int)strlen(filename), <,
		  (int)sizeof(sock_name.sun_path));
  strncpy(sock_name.sun_path, filename, sizeof(sock_name.sun_path));
  sock_name.sun_path[sizeof(sock_name.sun_path)-1] = '\0';
  g_assert_cmpint((int)bind(sock_fd, (struct sockaddr *)&sock_name,
			    (socklen_t)SUN_LEN(&sock_name)), >=, 0);
  task_context task = {
    .func=connect_question_socket,
    .question_filename=strdup(question_filename),
    .epoll_fd=epoll_fd,
    .password=&password,
    .filename=strdup(filename),
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=&mandos_client_exited,
    .password_is_read=&password_is_read,
    .current_time=&current_time,
  };
  g_assert_nonnull(task.question_filename);
  task.func(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);
  const task_context *const added_task
    = find_matching_task(queue, (task_context){
	.func=send_password_to_socket,
	.question_filename=question_filename,
	.filename=filename,
	.epoll_fd=epoll_fd,
	.password=&password,
	.cancelled_filenames=&cancelled_filenames,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
	.current_time=&current_time,
      });
  g_assert_nonnull(added_task);
  g_assert_cmpint(added_task->fd, >, 0);

  g_assert_true(epoll_set_contains(epoll_fd, added_task->fd,
				   EPOLLOUT));

  const int fd = added_task->fd;
  g_assert_cmpint(fd, >, 0);
  g_assert_true(fd_has_cloexec_and_nonblock(fd));

  /* write to fd */
  char write_data[PIPE_BUF];
  {
    /* Construct test password buffer */
    /* Start with + since that is what the real procotol uses */
    write_data[0] = '+';
    /* Set a special character at string end just to mark the end */
    write_data[sizeof(write_data)-2] = 'y';
    /* Set NUL at buffer end, as suggested by the protocol */
    write_data[sizeof(write_data)-1] = '\0';
    /* Fill rest of password with 'x' */
    memset(write_data+1, 'x', sizeof(write_data)-3);
    g_assert_cmpint((int)send(fd, write_data, sizeof(write_data),
			      MSG_NOSIGNAL), ==, sizeof(write_data));
  }

  /* read from sock_fd */
  char read_data[sizeof(write_data)];
  g_assert_cmpint((int)read(sock_fd, read_data, sizeof(read_data)),
		  ==, sizeof(read_data));

  g_assert_true(memcmp(write_data, read_data, sizeof(write_data))
		== 0);

  /* writing to sock_fd should fail */
  g_assert_cmpint(send(sock_fd, write_data, sizeof(write_data),
		       MSG_NOSIGNAL), <, 0);

  /* reading from fd should fail */
  g_assert_cmpint((int)recv(fd, read_data, sizeof(read_data),
			    MSG_NOSIGNAL), <, 0);

  g_assert_cmpint(unlink(filename), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static void
test_send_password_to_socket_client_not_exited(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(cleanup_string)))
    char *const filename = strdup("/nonexistent/socket");
  g_assert_nonnull(filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  bool password_is_read = true;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  const int write_socket = socketfds[1];
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=strdup(question_filename),
    .filename=strdup(filename),
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){false},
    .password_is_read=&password_is_read,
    .current_time=(mono_microsecs[]){0},
  };
  g_assert_nonnull(task.question_filename);

  task.func(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  const task_context *const added_task
    = find_matching_task(queue, task);
  g_assert_nonnull(added_task);
  g_assert_cmpuint((unsigned int)password.length, ==, 0);
  g_assert_true(password_is_read);

  g_assert_cmpint(added_task->fd, >, 0);
  g_assert_true(epoll_set_contains(epoll_fd, added_task->fd,
				   EPOLLOUT));
}

static void
test_send_password_to_socket_password_not_read(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(cleanup_string)))
    char *const filename = strdup("/nonexistent/socket");
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  buffer password = {};
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  const int write_socket = socketfds[1];
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=strdup(question_filename),
    .filename=strdup(filename),
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){false},
    .password_is_read=(bool[]){false},
    .current_time=(mono_microsecs[]){0},
  };
  g_assert_nonnull(task.question_filename);

  task.func(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  const task_context *const added_task = find_matching_task(queue,
							    task);
  g_assert_nonnull(added_task);
  g_assert_cmpuint((unsigned int)password.length, ==, 0);
  g_assert_true(queue->next_run == 0);

  g_assert_cmpint(added_task->fd, >, 0);
  g_assert_true(epoll_set_contains(epoll_fd, added_task->fd,
				   EPOLLOUT));
}

static
void test_send_password_to_socket_EMSGSIZE(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  const char question_filename[] = "/nonexistent/question";
  char *const filename = strdup("/nonexistent/socket");
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const size_t oversized = 1024*1024; /* Limit seems to be 212960 */
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(oversized),
    .length=oversized,
    .allocated=oversized,
  };
  g_assert_nonnull(password.data);
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }
  /* Construct test password buffer */
  /* Start with + since that is what the real procotol uses */
  password.data[0] = '+';
  /* Set a special character at string end just to mark the end */
  password.data[oversized-3] = 'y';
  /* Set NUL at buffer end, as suggested by the protocol */
  password.data[oversized-2] = '\0';
  /* Fill rest of password with 'x' */
  memset(password.data+1, 'x', oversized-3);

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  __attribute__((cleanup(cleanup_close)))
    const int write_socket = socketfds[1];
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=strdup(question_filename),
    .filename=filename,
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){true},
    .password_is_read=(bool[]){true},
    .current_time=(mono_microsecs[]){0},
  };
  g_assert_nonnull(task.question_filename);

  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
  g_assert_true(string_set_contains(cancelled_filenames,
				    question_filename));
}

static void test_send_password_to_socket_retry(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(cleanup_string)))
    char *const filename = strdup("/nonexistent/socket");
  g_assert_nonnull(filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  const int write_socket = socketfds[1];
  /* Close the server side socket to force ECONNRESET on client */
  g_assert_cmpint(close(read_socket), ==, 0);
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=strdup(question_filename),
    .filename=strdup(filename),
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){true},
    .password_is_read=(bool[]){true},
    .current_time=(mono_microsecs[]){0},
  };
  g_assert_nonnull(task.question_filename);

  task.func(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  const task_context *const added_task = find_matching_task(queue,
							    task);
  g_assert_nonnull(added_task);
  g_assert_cmpuint((unsigned int)password.length, ==, 0);

  g_assert_true(epoll_set_contains(epoll_fd, added_task->fd,
				   EPOLLOUT));
}

static
void test_send_password_to_socket_bad_epoll(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = open("/dev/null",
			      O_WRONLY | O_CLOEXEC | O_NOCTTY);
  __attribute__((cleanup(cleanup_string)))
    char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  __attribute__((cleanup(cleanup_string)))
    char *const filename = strdup("/nonexistent/socket");
  g_assert_nonnull(filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};

  const mono_microsecs current_time = 11;
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  const int write_socket = socketfds[1];
  /* Close the server side socket to force ECONNRESET on client */
  g_assert_cmpint(close(read_socket), ==, 0);
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=strdup(question_filename),
    .filename=strdup(filename),
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){true},
    .password_is_read=(bool[]){true},
    .current_time=&current_time,
  };
  g_assert_nonnull(task.question_filename);

  run_task_with_stderr_to_dev_null(task, queue);

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  const task_context *const added_task = find_matching_task(queue,
							    task);
  g_assert_nonnull(added_task);
  g_assert_true(queue->next_run == current_time + 1000000);
  g_assert_cmpuint((unsigned int)password.length, ==, 0);
}

static void assert_send_password_to_socket_password(buffer password){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  char *const question_filename = strdup("/nonexistent/question");
  g_assert_nonnull(question_filename);
  char *const filename = strdup("/nonexistent/socket");
  g_assert_nonnull(filename);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};

  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  int socketfds[2];
  g_assert_cmpint(socketpair(PF_LOCAL, SOCK_DGRAM
			     | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			     socketfds), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_socket = socketfds[0];
  const int write_socket = socketfds[1];
  task_context task = {
    .func=send_password_to_socket,
    .question_filename=question_filename,
    .filename=filename,
    .epoll_fd=epoll_fd,
    .fd=write_socket,
    .password=&password,
    .cancelled_filenames=&cancelled_filenames,
    .mandos_client_exited=(bool[]){true},
    .password_is_read=(bool[]){true},
    .current_time=(mono_microsecs[]){0},
  };

  char *expected_written_data = malloc(password.length + 2);
  g_assert_nonnull(expected_written_data);
  expected_written_data[0] = '+';
  expected_written_data[password.length + 1] = '\0';
  if(password.length > 0){
    g_assert_nonnull(password.data);
    memcpy(expected_written_data + 1, password.data, password.length);
  }

  task.func(task, queue);

  char buf[PIPE_BUF];
  g_assert_cmpint((int)read(read_socket, buf, PIPE_BUF), ==,
		  (int)(password.length + 2));
  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_true(memcmp(expected_written_data, buf,
		       password.length + 2) == 0);

  g_assert_true(epoll_set_does_not_contain(epoll_fd, write_socket));

  free(expected_written_data);
}

static void
test_send_password_to_socket_null_password(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  assert_send_password_to_socket_password(password);
}

static void
test_send_password_to_socket_empty_password(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(1),	       /* because malloc(0) may return NULL */
    .length=0,
    .allocated=0,		/* deliberate lie */
  };
  g_assert_nonnull(password.data);
  assert_send_password_to_socket_password(password);
}

static void
test_send_password_to_socket_empty_str_pass(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=strdup(""),
    .length=0,
    .allocated=1,
  };
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }
  assert_send_password_to_socket_password(password);
}

static void
test_send_password_to_socket_text_password(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  const char dummy_test_password[] = "dummy test password";
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data = strdup(dummy_test_password),
    .length = strlen(dummy_test_password),
    .allocated = sizeof(dummy_test_password),
  };
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }
  assert_send_password_to_socket_password(password);
}

static void
test_send_password_to_socket_binary_password(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(255),
    .length=255,
    .allocated=255,
  };
  g_assert_nonnull(password.data);
  if(mlock(password.data, password.allocated) != 0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }
  char c = 1;			/* Start at 1, avoiding NUL */
  for(int i=0; i < 255; i++){
    password.data[i] = c++;
  }
  assert_send_password_to_socket_password(password);
}

static void
test_send_password_to_socket_nuls_in_password(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  char test_password[] = {'\0', 'a', '\0', 'b', '\0', 'c', '\0'};
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {
    .data=malloc(sizeof(test_password)),
    .length=sizeof(test_password),
    .allocated=sizeof(test_password),
  };
  g_assert_nonnull(password.data);
  if(mlock(password.data, password.allocated) !=0){
    g_assert_true(errno == EPERM or errno == ENOMEM);
  }
  memcpy(password.data, test_password, password.allocated);
  assert_send_password_to_socket_password(password);
}

static bool assert_add_existing_questions_to_devnull(task_queue
						     *const,
						     const int,
						     buffer *const,
						     string_set *,
						     const
						     mono_microsecs
						     *const,
						     bool *const,
						     bool *const,
						     const char
						     *const);

static void test_add_existing_questions_ENOENT(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};

  g_assert_false(assert_add_existing_questions_to_devnull
		 (queue,
		  epoll_fd,
		  (buffer[]){{}}, /* password */
		  &cancelled_filenames,
		  (mono_microsecs[]){0}, /* current_time */
		  (bool[]){false},	 /* mandos_client_exited */
		  (bool[]){false},	 /* password_is_read */
		  "/nonexistent"));	 /* dirname */

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);
}

static
bool assert_add_existing_questions_to_devnull(task_queue
					      *const queue,
					      const int
					      epoll_fd,
					      buffer *const
					      password,
					      string_set
					      *cancelled_filenames,
					      const mono_microsecs
					      *const current_time,
					      bool *const
					      mandos_client_exited,
					      bool *const
					      password_is_read,
					      const char *const
					      dirname){
  __attribute__((cleanup(cleanup_close)))
    const int devnull_fd = open("/dev/null",
				O_WRONLY | O_CLOEXEC | O_NOCTTY);
  g_assert_cmpint(devnull_fd, >=, 0);
  __attribute__((cleanup(cleanup_close)))
    const int real_stderr_fd = dup(STDERR_FILENO);
  g_assert_cmpint(real_stderr_fd, >=, 0);
  dup2(devnull_fd, STDERR_FILENO);
  const bool ret = add_existing_questions(queue, epoll_fd, password,
					  cancelled_filenames,
					  current_time,
					  mandos_client_exited,
					  password_is_read, dirname);
  dup2(real_stderr_fd, STDERR_FILENO);
  return ret;
}

static
void test_add_existing_questions_no_questions(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);

  g_assert_false(assert_add_existing_questions_to_devnull
		 (queue,
		  epoll_fd,
		  (buffer[]){{}}, /* password */
		  &cancelled_filenames,
		  (mono_microsecs[]){0}, /* current_time */
		  (bool[]){false},	 /* mandos_client_exited */
		  (bool[]){false},	 /* password_is_read */
		  tempdir));

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static char *make_question_file_in_directory(const char *const);

static
void test_add_existing_questions_one_question(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename
    = make_question_file_in_directory(tempdir);
  g_assert_nonnull(question_filename);

  g_assert_true(assert_add_existing_questions_to_devnull
		(queue,
		 epoll_fd,
		 &password,
		 &cancelled_filenames,
		 &current_time,
		 &mandos_client_exited,
		 &password_is_read,
		 tempdir));

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=open_and_parse_question,
	.epoll_fd=epoll_fd,
	.filename=question_filename,
	.question_filename=question_filename,
	.password=&password,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(queue->next_run == 1);

  g_assert_cmpint(unlink(question_filename), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static char *make_question_file_in_directory(const char
					     *const dir){
  return make_temporary_prefixed_file_in_directory("ask.", dir);
}

static
void test_add_existing_questions_two_questions(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename1
    = make_question_file_in_directory(tempdir);
  g_assert_nonnull(question_filename1);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename2
    = make_question_file_in_directory(tempdir);
  g_assert_nonnull(question_filename2);

  g_assert_true(assert_add_existing_questions_to_devnull
		(queue,
		 epoll_fd,
		 &password,
		 &cancelled_filenames,
		 &current_time,
		 &mandos_client_exited,
		 &password_is_read,
		 tempdir));

  g_assert_cmpuint((unsigned int)queue->length, ==, 2);

  g_assert_true(queue->next_run == 1);

  __attribute__((cleanup(string_set_clear)))
    string_set seen_questions = {};

  bool queue_contains_question_opener(char *const question_filename){
    return(find_matching_task(queue, (task_context){
	  .func=open_and_parse_question,
	  .epoll_fd=epoll_fd,
	  .question_filename=question_filename,
	  .password=&password,
	  .cancelled_filenames=&cancelled_filenames,
	  .current_time=&current_time,
	  .mandos_client_exited=&mandos_client_exited,
	  .password_is_read=&password_is_read,
	}) != NULL);
  }

  g_assert_true(queue_contains_question_opener(question_filename1));
  g_assert_true(queue_contains_question_opener(question_filename2));

  g_assert_true(queue->next_run == 1);

  g_assert_cmpint(unlink(question_filename1), ==, 0);
  g_assert_cmpint(unlink(question_filename2), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static void
test_add_existing_questions_non_questions(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename1
    = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(question_filename1);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename2
    = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(question_filename2);

  g_assert_false(assert_add_existing_questions_to_devnull
		 (queue,
		  epoll_fd,
		  (buffer[]){{}}, /* password */
		  &cancelled_filenames,
		  (mono_microsecs[]){0}, /* current_time */
		  (bool[]){false},	 /* mandos_client_exited */
		  (bool[]){false},	 /* password_is_read */
		  tempdir));

  g_assert_cmpuint((unsigned int)queue->length, ==, 0);

  g_assert_cmpint(unlink(question_filename1), ==, 0);
  g_assert_cmpint(unlink(question_filename2), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static void
test_add_existing_questions_both_types(__attribute__((unused))
				       test_fixture *fixture,
				       __attribute__((unused))
				       gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  __attribute__((cleanup(cleanup_buffer)))
    buffer password = {};
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  const mono_microsecs current_time = 0;
  bool mandos_client_exited = false;
  bool password_is_read = false;
  __attribute__((cleanup(cleanup_string)))
    char *tempdir = make_temporary_directory();
  g_assert_nonnull(tempdir);
  __attribute__((cleanup(cleanup_string)))
    char *tempfilename1 = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(tempfilename1);
  __attribute__((cleanup(cleanup_string)))
    char *tempfilename2 = make_temporary_file_in_directory(tempdir);
  g_assert_nonnull(tempfilename2);
  __attribute__((cleanup(cleanup_string)))
    char *question_filename
    = make_question_file_in_directory(tempdir);
  g_assert_nonnull(question_filename);

  g_assert_true(assert_add_existing_questions_to_devnull
		(queue,
		 epoll_fd,
		 &password,
		 &cancelled_filenames,
		 &current_time,
		 &mandos_client_exited,
		 &password_is_read,
		 tempdir));

  g_assert_cmpuint((unsigned int)queue->length, ==, 1);

  g_assert_nonnull(find_matching_task(queue, (task_context){
	.func=open_and_parse_question,
	.epoll_fd=epoll_fd,
	.filename=question_filename,
	.question_filename=question_filename,
	.password=&password,
	.cancelled_filenames=&cancelled_filenames,
	.current_time=&current_time,
	.mandos_client_exited=&mandos_client_exited,
	.password_is_read=&password_is_read,
      }));

  g_assert_true(queue->next_run == 1);

  g_assert_cmpint(unlink(tempfilename1), ==, 0);
  g_assert_cmpint(unlink(tempfilename2), ==, 0);
  g_assert_cmpint(unlink(question_filename), ==, 0);
  g_assert_cmpint(rmdir(tempdir), ==, 0);
}

static void test_wait_for_event_timeout(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  g_assert_true(wait_for_event(epoll_fd, 1, 0));
}

static void test_wait_for_event_event(__attribute__((unused))
				      test_fixture *fixture,
				      __attribute__((unused))
				      gconstpointer user_data){
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);
  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_pipe = pipefds[0];
  __attribute__((cleanup(cleanup_close)))
    const int write_pipe = pipefds[1];
  g_assert_cmpint(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, read_pipe,
			    &(struct epoll_event)
			    { .events=EPOLLIN | EPOLLRDHUP }), ==, 0);
  g_assert_cmpint((int)write(write_pipe, "x", 1), ==, 1);

  g_assert_true(wait_for_event(epoll_fd, 0, 0));
}

static void test_wait_for_event_sigchld(test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  const pid_t pid = fork();
  if(pid == 0){		/* Child */
    if(not restore_signal_handler(&fixture->orig_sigaction)){
      _exit(EXIT_FAILURE);
    }
    if(not restore_sigmask(&fixture->orig_sigmask)){
      _exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
  }
  g_assert_true(pid != -1);
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  g_assert_cmpint(epoll_fd, >=, 0);

  g_assert_true(wait_for_event(epoll_fd, 0, 0));

  int status;
  g_assert_true(waitpid(pid, &status, 0) == pid);
  g_assert_true(WIFEXITED(status));
  g_assert_cmpint(WEXITSTATUS(status), ==, EXIT_SUCCESS);
}

static void test_run_queue_zeroes_next_run(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  queue->next_run = 1;
  __attribute__((cleanup(cleanup_close)))
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;

  g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)queue->next_run, ==, 0);
}

static
void test_run_queue_clears_cancelled_filenames(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;
  const char question_filename[] = "/nonexistent/question_filename";
  g_assert_true(string_set_add(&cancelled_filenames,
			       question_filename));

  g_assert_true(add_to_queue(queue,
			     (task_context){ .func=dummy_func }));

  g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)(queue->length), ==, 0);
  g_assert_false(string_set_contains(cancelled_filenames,
				     question_filename));
}

static
void test_run_queue_skips_cancelled_filenames(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;
  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_pipe = pipefds[0];
  g_assert_cmpint(close(pipefds[1]), ==, 0);
  const char question_filename[] = "/nonexistent/question_filename";
  g_assert_true(string_set_add(&cancelled_filenames,
			       question_filename));
  __attribute__((nonnull))
    void quit_func(const task_context task,
		   __attribute__((unused)) task_queue *const q){
    g_assert_nonnull(task.quit_now);
    *task.quit_now = true;
  }
  task_context task = {
    .func=quit_func,
    .question_filename=strdup(question_filename),
    .quit_now=&quit_now,
    .fd=read_pipe,
  };
  g_assert_nonnull(task.question_filename);

  g_assert_true(add_to_queue(queue, task));

  g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_false(quit_now);

  /* read_pipe should be closed already */
  errno = 0;
  bool read_pipe_closed = (close(read_pipe) == -1);
  read_pipe_closed &= (errno == EBADF);
  g_assert_true(read_pipe_closed);
}

static void test_run_queue_one_task(__attribute__((unused))
				    test_fixture *fixture,
				    __attribute__((unused))
				    gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;

  __attribute__((nonnull))
    void next_run_func(__attribute__((unused))
		       const task_context task,
		       task_queue *const q){
    q->next_run = 1;
  }

  task_context task = {
    .func=next_run_func,
  };
  g_assert_true(add_to_queue(queue, task));

  g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_cmpuint((unsigned int)(queue->next_run), ==, 1);
  g_assert_cmpuint((unsigned int)(queue->length), ==, 0);
}

static void test_run_queue_two_tasks(__attribute__((unused))
				     test_fixture *fixture,
				     __attribute__((unused))
				     gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  queue->next_run = 1;
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;
  bool mandos_client_exited = false;

  __attribute__((nonnull))
    void next_run_func(__attribute__((unused))
		       const task_context task,
		       task_queue *const q){
    q->next_run = 1;
  }

  __attribute__((nonnull))
    void exited_func(const task_context task,
		     __attribute__((unused)) task_queue *const q){
    *task.mandos_client_exited = true;
  }

  task_context task1 = {
    .func=next_run_func,
  };
  g_assert_true(add_to_queue(queue, task1));

  task_context task2 = {
    .func=exited_func,
    .mandos_client_exited=&mandos_client_exited,
  };
  g_assert_true(add_to_queue(queue, task2));

  g_assert_true(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_false(quit_now);
  g_assert_cmpuint((unsigned int)(queue->next_run), ==, 1);
  g_assert_true(mandos_client_exited);
  g_assert_cmpuint((unsigned int)(queue->length), ==, 0);
}

static void test_run_queue_two_tasks_quit(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  bool quit_now = false;
  bool mandos_client_exited = false;
  bool password_is_read = false;

  __attribute__((nonnull))
    void set_exited_func(const task_context task,
			 __attribute__((unused)) task_queue *const q){
    *task.mandos_client_exited = true;
    *task.quit_now = true;
  }
  task_context task1 = {
    .func=set_exited_func,
    .quit_now=&quit_now,
    .mandos_client_exited=&mandos_client_exited,
  };
  g_assert_true(add_to_queue(queue, task1));

  __attribute__((nonnull))
    void set_read_func(const task_context task,
		       __attribute__((unused)) task_queue *const q){
    *task.quit_now = true;
    *task.password_is_read = true;
  }
  task_context task2 = {
    .func=set_read_func,
    .quit_now=&quit_now,
    .password_is_read=&password_is_read,
  };
  g_assert_true(add_to_queue(queue, task2));

  g_assert_false(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_true(quit_now);
  g_assert_true(mandos_client_exited xor password_is_read);
  g_assert_cmpuint((unsigned int)(queue->length), ==, 0);
}

static void test_run_queue_two_tasks_cleanup(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  __attribute__((cleanup(cleanup_queue)))
    task_queue *queue = create_queue();
  g_assert_nonnull(queue);
  __attribute__((cleanup(string_set_clear)))
    string_set cancelled_filenames = {};
  int pipefds[2];
  g_assert_cmpint(pipe2(pipefds, O_CLOEXEC | O_NONBLOCK), ==, 0);
  __attribute__((cleanup(cleanup_close)))
    const int read_pipe = pipefds[0];
  __attribute__((cleanup(cleanup_close)))
    const int write_pipe = pipefds[1];
  bool quit_now = false;

  __attribute__((nonnull))
    void read_func(const task_context task,
		   __attribute__((unused)) task_queue *const q){
    *task.quit_now = true;
  }
  task_context task1 = {
    .func=read_func,
    .quit_now=&quit_now,
    .fd=read_pipe,
  };
  g_assert_true(add_to_queue(queue, task1));

  __attribute__((nonnull))
    void write_func(const task_context task,
		    __attribute__((unused)) task_queue *const q){
    *task.quit_now = true;
  }
  task_context task2 = {
    .func=write_func,
    .quit_now=&quit_now,
    .fd=write_pipe,
  };
  g_assert_true(add_to_queue(queue, task2));

  g_assert_false(run_queue(&queue, &cancelled_filenames, &quit_now));
  g_assert_true(quit_now);

  /* Either read_pipe or write_pipe should be closed already */
  errno = 0;
  bool close_read_pipe = (close(read_pipe) == -1);
  close_read_pipe &= (errno == EBADF);
  errno = 0;
  bool close_write_pipe = (close(write_pipe) == -1);
  close_write_pipe &= (errno == EBADF);
  g_assert_true(close_read_pipe xor close_write_pipe);
  g_assert_cmpuint((unsigned int)(queue->length), ==, 0);
}

static void test_setup_signal_handler(__attribute__((unused))
				      test_fixture *fixture,
				      __attribute__((unused))
				      gconstpointer user_data){
  /* Save current SIGCHLD action, whatever it is */
  struct sigaction expected_sigchld_action;
  g_assert_cmpint(sigaction(SIGCHLD, NULL, &expected_sigchld_action),
		  ==, 0);

  /* Act; i.e. run the setup_signal_handler() function */
  struct sigaction actual_old_sigchld_action;
  g_assert_true(setup_signal_handler(&actual_old_sigchld_action));

  /* Check that the function correctly set "actual_old_sigchld_action"
     to the same values as the previously saved
     "expected_sigchld_action" */
  /* Check member sa_handler */
  g_assert_true(actual_old_sigchld_action.sa_handler
		== expected_sigchld_action.sa_handler);
  /* Check member sa_mask */
  for(int signum = 1; signum < NSIG; signum++){
    const int expected_old_block_state
      = sigismember(&expected_sigchld_action.sa_mask, signum);
    g_assert_cmpint(expected_old_block_state, >=, 0);
    const int actual_old_block_state
      = sigismember(&actual_old_sigchld_action.sa_mask, signum);
    g_assert_cmpint(actual_old_block_state, >=, 0);
    g_assert_cmpint(actual_old_block_state,
		    ==, expected_old_block_state);
  }
  /* Check member sa_flags */
  g_assert_true((actual_old_sigchld_action.sa_flags
		 & (SA_NOCLDSTOP | SA_ONSTACK | SA_RESTART))
		== (expected_sigchld_action.sa_flags
		    & (SA_NOCLDSTOP | SA_ONSTACK | SA_RESTART)));

  /* Retrieve the current signal handler for SIGCHLD as set by
     setup_signal_handler() */
  struct sigaction actual_new_sigchld_action;
  g_assert_cmpint(sigaction(SIGCHLD, NULL,
			    &actual_new_sigchld_action), ==, 0);
  /* Check that the signal handler (member sa_handler) is correctly
     set to the "handle_sigchld" function */
  g_assert_true(actual_new_sigchld_action.sa_handler != SIG_DFL);
  g_assert_true(actual_new_sigchld_action.sa_handler != SIG_IGN);
  g_assert_true(actual_new_sigchld_action.sa_handler
		== handle_sigchld);
  /* Check (in member sa_mask) that at least a handful of signals are
     actually blocked during the signal handler */
  for(int signum = 1; signum < NSIG; signum++){
    int actual_new_block_state;
    switch(signum){
    case SIGTERM:
    case SIGINT:
    case SIGQUIT:
    case SIGHUP:
      actual_new_block_state
	= sigismember(&actual_new_sigchld_action.sa_mask, signum);
      g_assert_cmpint(actual_new_block_state, ==, 1);
      continue;
    case SIGKILL:		/* non-blockable */
    case SIGSTOP:		/* non-blockable */
    case SIGCHLD:		/* always blocked */
    default:
      continue;
    }
  }
  /* Check member sa_flags */
  g_assert_true((actual_new_sigchld_action.sa_flags
		 & (SA_NOCLDSTOP | SA_ONSTACK | SA_RESTART))
		== (SA_NOCLDSTOP | SA_RESTART));

  /* Restore signal handler */
  g_assert_cmpint(sigaction(SIGCHLD, &expected_sigchld_action, NULL),
		  ==, 0);
}

static void test_restore_signal_handler(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  /* Save current SIGCHLD action, whatever it is */
  struct sigaction expected_sigchld_action;
  g_assert_cmpint(sigaction(SIGCHLD, NULL, &expected_sigchld_action),
		  ==, 0);
  /* Since we haven't established a signal handler yet, there should
     not be one established.  But another test may have relied on
     restore_signal_handler() to restore the signal handler, and if
     restore_signal_handler() is buggy (which we should be prepared
     for in this test) the signal handler may not have been restored
     properly; check for this: */
  g_assert_true(expected_sigchld_action.sa_handler != handle_sigchld);

  /* Establish a signal handler */
  struct sigaction sigchld_action = {
    .sa_handler=handle_sigchld,
    .sa_flags=SA_RESTART | SA_NOCLDSTOP,
  };
  g_assert_cmpint(sigfillset(&sigchld_action.sa_mask), ==, 0);
  g_assert_cmpint(sigaction(SIGCHLD, &sigchld_action, NULL), ==, 0);

  /* Act; i.e. run the restore_signal_handler() function */
  g_assert_true(restore_signal_handler(&expected_sigchld_action));

  /* Retrieve the restored signal handler data */
  struct sigaction actual_restored_sigchld_action;
  g_assert_cmpint(sigaction(SIGCHLD, NULL,
			    &actual_restored_sigchld_action), ==, 0);

  /* Check that the function correctly restored the signal action, as
     saved in "actual_restored_sigchld_action", to the same values as
     the previously saved "expected_sigchld_action" */
  /* Check member sa_handler */
  g_assert_true(actual_restored_sigchld_action.sa_handler
		== expected_sigchld_action.sa_handler);
  /* Check member sa_mask */
  for(int signum = 1; signum < NSIG; signum++){
    const int expected_old_block_state
      = sigismember(&expected_sigchld_action.sa_mask, signum);
    g_assert_cmpint(expected_old_block_state, >=, 0);
    const int actual_restored_block_state
      = sigismember(&actual_restored_sigchld_action.sa_mask, signum);
    g_assert_cmpint(actual_restored_block_state, >=, 0);
    g_assert_cmpint(actual_restored_block_state,
		    ==, expected_old_block_state);
  }
  /* Check member sa_flags */
  g_assert_true((actual_restored_sigchld_action.sa_flags
		 & (SA_NOCLDSTOP | SA_ONSTACK | SA_RESTART))
		== (expected_sigchld_action.sa_flags
		    & (SA_NOCLDSTOP | SA_ONSTACK | SA_RESTART)));
}

static void test_block_sigchld(__attribute__((unused))
			       test_fixture *fixture,
			       __attribute__((unused))
			       gconstpointer user_data){
  /* Save original signal mask */
  sigset_t expected_sigmask;
  g_assert_cmpint(pthread_sigmask(-1, NULL, &expected_sigmask),
		  ==, 0);

  /* Make sure SIGCHLD is unblocked for this test */
  sigset_t sigchld_sigmask;
  g_assert_cmpint(sigemptyset(&sigchld_sigmask), ==, 0);
  g_assert_cmpint(sigaddset(&sigchld_sigmask, SIGCHLD), ==, 0);
  g_assert_cmpint(pthread_sigmask(SIG_UNBLOCK, &sigchld_sigmask,
				  NULL), ==, 0);

  /* Act; i.e. run the block_sigchld() function */
  sigset_t actual_old_sigmask;
  g_assert_true(block_sigchld(&actual_old_sigmask));

  /* Check the actual_old_sigmask; it should be the same as the
     previously saved signal mask "expected_sigmask". */
  for(int signum = 1; signum < NSIG; signum++){
    const int expected_old_block_state
      = sigismember(&expected_sigmask, signum);
    g_assert_cmpint(expected_old_block_state, >=, 0);
    const int actual_old_block_state
      = sigismember(&actual_old_sigmask, signum);
    g_assert_cmpint(actual_old_block_state, >=, 0);
    g_assert_cmpint(actual_old_block_state,
		    ==, expected_old_block_state);
  }

  /* Retrieve the newly set signal mask */
  sigset_t actual_sigmask;
  g_assert_cmpint(pthread_sigmask(-1, NULL, &actual_sigmask), ==, 0);

  /* SIGCHLD should be blocked */
  g_assert_cmpint(sigismember(&actual_sigmask, SIGCHLD), ==, 1);

  /* Restore signal mask */
  g_assert_cmpint(pthread_sigmask(SIG_SETMASK, &expected_sigmask,
				  NULL), ==, 0);
}

static void test_restore_sigmask(__attribute__((unused))
				 test_fixture *fixture,
				 __attribute__((unused))
				 gconstpointer user_data){
  /* Save original signal mask */
  sigset_t orig_sigmask;
  g_assert_cmpint(pthread_sigmask(-1, NULL, &orig_sigmask), ==, 0);

  /* Make sure SIGCHLD is blocked for this test */
  sigset_t sigchld_sigmask;
  g_assert_cmpint(sigemptyset(&sigchld_sigmask), ==, 0);
  g_assert_cmpint(sigaddset(&sigchld_sigmask, SIGCHLD), ==, 0);
  g_assert_cmpint(pthread_sigmask(SIG_BLOCK, &sigchld_sigmask,
				  NULL), ==, 0);

  /* Act; i.e. run the restore_sigmask() function */
  g_assert_true(restore_sigmask(&orig_sigmask));

  /* Retrieve the newly restored signal mask */
  sigset_t restored_sigmask;
  g_assert_cmpint(pthread_sigmask(-1, NULL, &restored_sigmask),
		  ==, 0);

  /* Check the restored_sigmask; it should be the same as the
     previously saved signal mask "orig_sigmask". */
  for(int signum = 1; signum < NSIG; signum++){
    const int orig_block_state = sigismember(&orig_sigmask, signum);
    g_assert_cmpint(orig_block_state, >=, 0);
    const int restored_block_state = sigismember(&restored_sigmask,
						 signum);
    g_assert_cmpint(restored_block_state, >=, 0);
    g_assert_cmpint(restored_block_state, ==, orig_block_state);
  }

  /* Restore signal mask */
  g_assert_cmpint(pthread_sigmask(SIG_SETMASK, &orig_sigmask,
				  NULL), ==, 0);
}

static void test_parse_arguments_noargs(__attribute__((unused))
					test_fixture *fixture,
					__attribute__((unused))
					gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));
  g_assert_null(agent_directory);
  g_assert_null(helper_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

__attribute__((nonnull))
static bool parse_arguments_devnull(int argc, char *argv[],
				    const bool exit_failure,
				    char **agent_directory,
				    char **helper_directory,
				    uid_t *const user,
				    gid_t *const group,
				    char **mandos_argz,
				    size_t *mandos_argz_length){

  FILE *real_stderr = stderr;
  FILE *devnull = fopen("/dev/null", "we");
  g_assert_nonnull(devnull);
  stderr = devnull;

  const bool ret = parse_arguments(argc, argv, exit_failure,
				   agent_directory,
				   helper_directory, user, group,
				   mandos_argz, mandos_argz_length);
  const error_t saved_errno = errno;

  stderr = real_stderr;
  g_assert_cmpint(fclose(devnull), ==, 0);

  errno = saved_errno;

  return ret;
}

static void test_parse_arguments_invalid(__attribute__((unused))
					 test_fixture *fixture,
					 __attribute__((unused))
					 gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--invalid"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_false(parse_arguments_devnull(argc, argv, false,
					 &agent_directory,
					 &helper_directory, &user,
					 &group, &mandos_argz,
					 &mandos_argz_length));

  g_assert_true(errno == EINVAL);
  g_assert_null(agent_directory);
  g_assert_null(helper_directory);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_long_dir(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--agent-directory"),
    strdup("/tmp"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(agent_directory, ==, "/tmp");
  g_assert_null(helper_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_short_dir(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("-d"),
    strdup("/tmp"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(agent_directory, ==, "/tmp");
  g_assert_null(helper_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static
void test_parse_arguments_helper_directory(__attribute__((unused))
					   test_fixture *fixture,
					   __attribute__((unused))
					   gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--helper-directory"),
    strdup("/tmp"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(helper_directory, ==, "/tmp");
  g_assert_null(agent_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static
void test_parse_arguments_plugin_helper_dir(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--plugin-helper-dir"),
    strdup("/tmp"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(helper_directory, ==, "/tmp");
  g_assert_null(agent_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_user(__attribute__((unused))
				      test_fixture *fixture,
				      __attribute__((unused))
				      gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--user"),
    strdup("1000"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_cmpuint((unsigned int)user, ==, 1000);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_user_invalid(__attribute__((unused))
					      test_fixture *fixture,
					      __attribute__((unused))
					      gconstpointer
					      user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--user"),
    strdup("invalid"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_false(parse_arguments_devnull(argc, argv, false,
					 &agent_directory,
					 &helper_directory, &user,
					 &group, &mandos_argz,
					 &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_cmpuint((unsigned int)user, ==, 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static
void test_parse_arguments_user_zero_invalid(__attribute__((unused))
					    test_fixture *fixture,
					    __attribute__((unused))
					    gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--user"),
    strdup("0"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_false(parse_arguments_devnull(argc, argv, false,
					 &agent_directory,
					 &helper_directory, &user,
					 &group, &mandos_argz,
					 &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_cmpuint((unsigned int)user, ==, 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_group(__attribute__((unused))
				       test_fixture *fixture,
				       __attribute__((unused))
				       gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--group"),
    strdup("1000"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_true(user == 0);
  g_assert_cmpuint((unsigned int)group, ==, 1000);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_group_invalid(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--group"),
    strdup("invalid"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_false(parse_arguments_devnull(argc, argv, false,
					 &agent_directory,
					 &helper_directory, &user,
					 &group, &mandos_argz,
					 &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static
void test_parse_arguments_group_zero_invalid(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--group"),
    strdup("0"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_false(parse_arguments_devnull(argc, argv, false,
					 &agent_directory,
					 &helper_directory, &user,
					 &group, &mandos_argz,
					 &mandos_argz_length));

  g_assert_null(helper_directory);
  g_assert_null(agent_directory);
  g_assert_cmpuint((unsigned int)group, ==, 0);
  g_assert_true(group == 0);
  g_assert_null(mandos_argz);
  g_assert_true(mandos_argz_length == 0);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_mandos_noargs(__attribute__((unused))
					       test_fixture *fixture,
					       __attribute__((unused))
					       gconstpointer
					       user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("mandos-client"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_null(agent_directory);
  g_assert_null(helper_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  g_assert_cmpstr(mandos_argz, ==, "mandos-client");
  g_assert_cmpuint((unsigned int)argz_count(mandos_argz,
					    mandos_argz_length),
		   ==, 1);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_mandos_args(__attribute__((unused))
					     test_fixture *fixture,
					     __attribute__((unused))
					     gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("mandos-client"),
    strdup("one"),
    strdup("two"),
    strdup("three"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_null(agent_directory);
  g_assert_null(helper_directory);
  g_assert_true(user == 0);
  g_assert_true(group == 0);
  char *marg = mandos_argz;
  g_assert_cmpstr(marg, ==, "mandos-client");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "one");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "two");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "three");
  g_assert_cmpuint((unsigned int)argz_count(mandos_argz,
					    mandos_argz_length),
		   ==, 4);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_all_args(__attribute__((unused))
					  test_fixture *fixture,
					  __attribute__((unused))
					  gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("--agent-directory"),
    strdup("/tmp"),
    strdup("--helper-directory"),
    strdup("/var/tmp"),
    strdup("--user"),
    strdup("1"),
    strdup("--group"),
    strdup("2"),
    strdup("mandos-client"),
    strdup("one"),
    strdup("two"),
    strdup("three"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(agent_directory, ==, "/tmp");
  g_assert_cmpstr(helper_directory, ==, "/var/tmp");
  g_assert_true(user == 1);
  g_assert_true(group == 2);
  char *marg = mandos_argz;
  g_assert_cmpstr(marg, ==, "mandos-client");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "one");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "two");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "three");
  g_assert_cmpuint((unsigned int)argz_count(mandos_argz,
					    mandos_argz_length),
		   ==, 4);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

static void test_parse_arguments_mixed(__attribute__((unused))
				       test_fixture *fixture,
				       __attribute__((unused))
				       gconstpointer user_data){
  char *argv[] = {
    strdup("prgname"),
    strdup("mandos-client"),
    strdup("--user"),
    strdup("1"),
    strdup("one"),
    strdup("--agent-directory"),
    strdup("/tmp"),
    strdup("two"),
    strdup("three"),
    strdup("--helper-directory=/var/tmp"),
    NULL };
  const int argc = (sizeof(argv) / sizeof(char *)) - 1;

  __attribute__((cleanup(cleanup_string)))
    char *agent_directory = NULL;
  __attribute__((cleanup(cleanup_string)))
    char *helper_directory = NULL;
  uid_t user = 0;
  gid_t group = 0;
  __attribute__((cleanup(cleanup_string)))
    char *mandos_argz = NULL;
  size_t mandos_argz_length = 0;

  g_assert_true(parse_arguments(argc, argv, false, &agent_directory,
				&helper_directory, &user, &group,
				&mandos_argz, &mandos_argz_length));

  g_assert_cmpstr(agent_directory, ==, "/tmp");
  g_assert_cmpstr(helper_directory, ==, "/var/tmp");
  g_assert_true(user == 1);
  g_assert_true(group == 0);
  char *marg = mandos_argz;
  g_assert_cmpstr(marg, ==, "mandos-client");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "one");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "two");
  marg = argz_next(mandos_argz, mandos_argz_length, marg);
  g_assert_cmpstr(marg, ==, "three");
  g_assert_cmpuint((unsigned int)argz_count(mandos_argz,
					    mandos_argz_length),
		   ==, 4);

  for(char **arg = argv; *arg != NULL; arg++){
    free(*arg);
  }
}

/* End of tests section */

/* Test boilerplate section; New tests should be added to the test
   suite definition here, in the "run_tests" function.

   Finally, this section also contains the should_only_run_tests()
   function used by main() for deciding if tests should be run or to
   start normally. */

__attribute__((cold))
static bool run_tests(int argc, char *argv[]){
  g_test_init(&argc, &argv, NULL);

  /* A macro to add a test with no setup or teardown functions */
#define test_add(testpath, testfunc)			\
  do {							\
    g_test_add((testpath), test_fixture, NULL, NULL,	\
	       (testfunc), NULL);			\
  } while(false)

  /* Test the signal-related functions first, since some other tests
     depend on these functions in their setups and teardowns */
  test_add("/signal-handling/setup", test_setup_signal_handler);
  test_add("/signal-handling/restore", test_restore_signal_handler);
  test_add("/signal-handling/block", test_block_sigchld);
  test_add("/signal-handling/restore-sigmask", test_restore_sigmask);

  /* Regular non-signal-related tests; these use no setups or
     teardowns */
  test_add("/parse_arguments/noargs", test_parse_arguments_noargs);
  test_add("/parse_arguments/invalid", test_parse_arguments_invalid);
  test_add("/parse_arguments/long-dir",
	   test_parse_arguments_long_dir);
  test_add("/parse_arguments/short-dir",
	   test_parse_arguments_short_dir);
  test_add("/parse_arguments/helper-directory",
	   test_parse_arguments_helper_directory);
  test_add("/parse_arguments/plugin-helper-dir",
	   test_parse_arguments_plugin_helper_dir);
  test_add("/parse_arguments/user", test_parse_arguments_user);
  test_add("/parse_arguments/user-invalid",
  	   test_parse_arguments_user_invalid);
  test_add("/parse_arguments/user-zero-invalid",
  	   test_parse_arguments_user_zero_invalid);
  test_add("/parse_arguments/group", test_parse_arguments_group);
  test_add("/parse_arguments/group-invalid",
  	   test_parse_arguments_group_invalid);
  test_add("/parse_arguments/group-zero-invalid",
  	   test_parse_arguments_group_zero_invalid);
  test_add("/parse_arguments/mandos-noargs",
	   test_parse_arguments_mandos_noargs);
  test_add("/parse_arguments/mandos-args",
	   test_parse_arguments_mandos_args);
  test_add("/parse_arguments/all-args",
	   test_parse_arguments_all_args);
  test_add("/parse_arguments/mixed", test_parse_arguments_mixed);
  test_add("/queue/create", test_create_queue);
  test_add("/queue/add", test_add_to_queue);
  test_add("/queue/has_question/empty",
	   test_queue_has_question_empty);
  test_add("/queue/has_question/false",
	   test_queue_has_question_false);
  test_add("/queue/has_question/true", test_queue_has_question_true);
  test_add("/queue/has_question/false2",
	   test_queue_has_question_false2);
  test_add("/queue/has_question/true2",
	   test_queue_has_question_true2);
  test_add("/buffer/cleanup", test_cleanup_buffer);
  test_add("/string_set/net-set-contains-nothing",
	   test_string_set_new_set_contains_nothing);
  test_add("/string_set/with-added-string-contains-it",
	   test_string_set_with_added_string_contains_it);
  test_add("/string_set/cleared-does-not-contain-string",
	   test_string_set_cleared_does_not_contain_str);
  test_add("/string_set/swap/one-with-empty",
	   test_string_set_swap_one_with_empty);
  test_add("/string_set/swap/empty-with-one",
	   test_string_set_swap_empty_with_one);
  test_add("/string_set/swap/one-with-one",
	   test_string_set_swap_one_with_one);

  /* A macro to add a test using the setup and teardown functions */
#define test_add_st(path, func)					\
  do {								\
    g_test_add((path), test_fixture, NULL, test_setup, (func),	\
	       test_teardown);					\
  } while(false)

  /* Signal-related tests; these use setups and teardowns which
     establish, during each test run, a signal handler for, and a
     signal mask blocking, the SIGCHLD signal, just like main() */
  test_add_st("/wait_for_event/timeout", test_wait_for_event_timeout);
  test_add_st("/wait_for_event/event", test_wait_for_event_event);
  test_add_st("/wait_for_event/sigchld", test_wait_for_event_sigchld);
  test_add_st("/run_queue/zeroes-next-run",
	      test_run_queue_zeroes_next_run);
  test_add_st("/run_queue/clears-cancelled_filenames",
	      test_run_queue_clears_cancelled_filenames);
  test_add_st("/run_queue/skips-cancelled-filenames",
  	      test_run_queue_skips_cancelled_filenames);
  test_add_st("/run_queue/one-task", test_run_queue_one_task);
  test_add_st("/run_queue/two-tasks", test_run_queue_two_tasks);
  test_add_st("/run_queue/two-tasks/quit",
	      test_run_queue_two_tasks_quit);
  test_add_st("/run_queue/two-tasks-cleanup",
	      test_run_queue_two_tasks_cleanup);
  test_add_st("/task-creators/start_mandos_client",
	      test_start_mandos_client);
  test_add_st("/task-creators/start_mandos_client/execv",
	      test_start_mandos_client_execv);
  test_add_st("/task-creators/start_mandos_client/suid/euid",
	      test_start_mandos_client_suid_euid);
  test_add_st("/task-creators/start_mandos_client/suid/egid",
  	      test_start_mandos_client_suid_egid);
  test_add_st("/task-creators/start_mandos_client/suid/ruid",
  	      test_start_mandos_client_suid_ruid);
  test_add_st("/task-creators/start_mandos_client/suid/rgid",
  	      test_start_mandos_client_suid_rgid);
  test_add_st("/task-creators/start_mandos_client/read",
	      test_start_mandos_client_read);
  test_add_st("/task-creators/start_mandos_client/helper-directory",
	      test_start_mandos_client_helper_directory);
  test_add_st("/task-creators/start_mandos_client/sigmask",
	      test_start_mandos_client_sigmask);
  test_add_st("/task/wait_for_mandos_client_exit/badpid",
	      test_wait_for_mandos_client_exit_badpid);
  test_add_st("/task/wait_for_mandos_client_exit/noexit",
	      test_wait_for_mandos_client_exit_noexit);
  test_add_st("/task/wait_for_mandos_client_exit/success",
	      test_wait_for_mandos_client_exit_success);
  test_add_st("/task/wait_for_mandos_client_exit/failure",
	      test_wait_for_mandos_client_exit_failure);
  test_add_st("/task/wait_for_mandos_client_exit/killed",
	      test_wait_for_mandos_client_exit_killed);
  test_add_st("/task/read_mandos_client_output/readerror",
	      test_read_mandos_client_output_readerror);
  test_add_st("/task/read_mandos_client_output/nodata",
	      test_read_mandos_client_output_nodata);
  test_add_st("/task/read_mandos_client_output/eof",
	      test_read_mandos_client_output_eof);
  test_add_st("/task/read_mandos_client_output/once",
	      test_read_mandos_client_output_once);
  test_add_st("/task/read_mandos_client_output/malloc",
	      test_read_mandos_client_output_malloc);
  test_add_st("/task/read_mandos_client_output/append",
	      test_read_mandos_client_output_append);
  test_add_st("/task-creators/add_inotify_dir_watch",
	      test_add_inotify_dir_watch);
  test_add_st("/task-creators/add_inotify_dir_watch/fail",
	      test_add_inotify_dir_watch_fail);
  test_add_st("/task-creators/add_inotify_dir_watch/not-a-directory",
	      test_add_inotify_dir_watch_nondir);
  test_add_st("/task-creators/add_inotify_dir_watch/EAGAIN",
	      test_add_inotify_dir_watch_EAGAIN);
  test_add_st("/task-creators/add_inotify_dir_watch/IN_CLOSE_WRITE",
	      test_add_inotify_dir_watch_IN_CLOSE_WRITE);
  test_add_st("/task-creators/add_inotify_dir_watch/IN_MOVED_TO",
	      test_add_inotify_dir_watch_IN_MOVED_TO);
  test_add_st("/task-creators/add_inotify_dir_watch/IN_MOVED_FROM",
	      test_add_inotify_dir_watch_IN_MOVED_FROM);
  test_add_st("/task-creators/add_inotify_dir_watch/IN_EXCL_UNLINK",
	      test_add_inotify_dir_watch_IN_EXCL_UNLINK);
  test_add_st("/task-creators/add_inotify_dir_watch/IN_DELETE",
	      test_add_inotify_dir_watch_IN_DELETE);
  test_add_st("/task/read_inotify_event/readerror",
	      test_read_inotify_event_readerror);
  test_add_st("/task/read_inotify_event/bad-epoll",
	      test_read_inotify_event_bad_epoll);
  test_add_st("/task/read_inotify_event/nodata",
	      test_read_inotify_event_nodata);
  test_add_st("/task/read_inotify_event/eof",
	      test_read_inotify_event_eof);
  test_add_st("/task/read_inotify_event/IN_CLOSE_WRITE",
	      test_read_inotify_event_IN_CLOSE_WRITE);
  test_add_st("/task/read_inotify_event/IN_MOVED_TO",
	      test_read_inotify_event_IN_MOVED_TO);
  test_add_st("/task/read_inotify_event/IN_MOVED_FROM",
	      test_read_inotify_event_IN_MOVED_FROM);
  test_add_st("/task/read_inotify_event/IN_DELETE",
	      test_read_inotify_event_IN_DELETE);
  test_add_st("/task/read_inotify_event/IN_CLOSE_WRITE/badname",
	      test_read_inotify_event_IN_CLOSE_WRITE_badname);
  test_add_st("/task/read_inotify_event/IN_MOVED_TO/badname",
	      test_read_inotify_event_IN_MOVED_TO_badname);
  test_add_st("/task/read_inotify_event/IN_MOVED_FROM/badname",
	      test_read_inotify_event_IN_MOVED_FROM_badname);
  test_add_st("/task/read_inotify_event/IN_DELETE/badname",
	      test_read_inotify_event_IN_DELETE_badname);
  test_add_st("/task/open_and_parse_question/ENOENT",
	      test_open_and_parse_question_ENOENT);
  test_add_st("/task/open_and_parse_question/EIO",
	      test_open_and_parse_question_EIO);
  test_add_st("/task/open_and_parse_question/parse-error",
	      test_open_and_parse_question_parse_error);
  test_add_st("/task/open_and_parse_question/nosocket",
	      test_open_and_parse_question_nosocket);
  test_add_st("/task/open_and_parse_question/badsocket",
	      test_open_and_parse_question_badsocket);
  test_add_st("/task/open_and_parse_question/nopid",
	      test_open_and_parse_question_nopid);
  test_add_st("/task/open_and_parse_question/badpid",
	      test_open_and_parse_question_badpid);
  test_add_st("/task/open_and_parse_question/noexist_pid",
	      test_open_and_parse_question_noexist_pid);
  test_add_st("/task/open_and_parse_question/no-notafter",
	      test_open_and_parse_question_no_notafter);
  test_add_st("/task/open_and_parse_question/bad-notafter",
	      test_open_and_parse_question_bad_notafter);
  test_add_st("/task/open_and_parse_question/notafter-0",
	      test_open_and_parse_question_notafter_0);
  test_add_st("/task/open_and_parse_question/notafter-1",
	      test_open_and_parse_question_notafter_1);
  test_add_st("/task/open_and_parse_question/notafter-1-1",
	      test_open_and_parse_question_notafter_1_1);
  test_add_st("/task/open_and_parse_question/notafter-1-2",
	      test_open_and_parse_question_notafter_1_2);
  test_add_st("/task/open_and_parse_question/equal-notafter",
	      test_open_and_parse_question_equal_notafter);
  test_add_st("/task/open_and_parse_question/late-notafter",
	      test_open_and_parse_question_late_notafter);
  test_add_st("/task/cancel_old_question/0-1-2",
	      test_cancel_old_question_0_1_2);
  test_add_st("/task/cancel_old_question/0-2-1",
	      test_cancel_old_question_0_2_1);
  test_add_st("/task/cancel_old_question/1-2-3",
	      test_cancel_old_question_1_2_3);
  test_add_st("/task/cancel_old_question/1-3-2",
	      test_cancel_old_question_1_3_2);
  test_add_st("/task/cancel_old_question/2-1-3",
	      test_cancel_old_question_2_1_3);
  test_add_st("/task/cancel_old_question/2-3-1",
	      test_cancel_old_question_2_3_1);
  test_add_st("/task/cancel_old_question/3-1-2",
	      test_cancel_old_question_3_1_2);
  test_add_st("/task/cancel_old_question/3-2-1",
	      test_cancel_old_question_3_2_1);
  test_add_st("/task/connect_question_socket/name-too-long",
	      test_connect_question_socket_name_too_long);
  test_add_st("/task/connect_question_socket/connect-fail",
	      test_connect_question_socket_connect_fail);
  test_add_st("/task/connect_question_socket/bad-epoll",
	      test_connect_question_socket_bad_epoll);
  test_add_st("/task/connect_question_socket/usable",
	      test_connect_question_socket_usable);
  test_add_st("/task/send_password_to_socket/client-not-exited",
	      test_send_password_to_socket_client_not_exited);
  test_add_st("/task/send_password_to_socket/password-not-read",
	      test_send_password_to_socket_password_not_read);
  test_add_st("/task/send_password_to_socket/EMSGSIZE",
	      test_send_password_to_socket_EMSGSIZE);
  test_add_st("/task/send_password_to_socket/retry",
	      test_send_password_to_socket_retry);
  test_add_st("/task/send_password_to_socket/bad-epoll",
	      test_send_password_to_socket_bad_epoll);
  test_add_st("/task/send_password_to_socket/null-password",
	      test_send_password_to_socket_null_password);
  test_add_st("/task/send_password_to_socket/empty-password",
	      test_send_password_to_socket_empty_password);
  test_add_st("/task/send_password_to_socket/empty-str-password",
	      test_send_password_to_socket_empty_str_pass);
  test_add_st("/task/send_password_to_socket/text-password",
	      test_send_password_to_socket_text_password);
  test_add_st("/task/send_password_to_socket/binary-password",
	      test_send_password_to_socket_binary_password);
  test_add_st("/task/send_password_to_socket/nuls-in-password",
	      test_send_password_to_socket_nuls_in_password);
  test_add_st("/task-creators/add_existing_questions/ENOENT",
	      test_add_existing_questions_ENOENT);
  test_add_st("/task-creators/add_existing_questions/no-questions",
	      test_add_existing_questions_no_questions);
  test_add_st("/task-creators/add_existing_questions/one-question",
	      test_add_existing_questions_one_question);
  test_add_st("/task-creators/add_existing_questions/two-questions",
	      test_add_existing_questions_two_questions);
  test_add_st("/task-creators/add_existing_questions/non-questions",
	      test_add_existing_questions_non_questions);
  test_add_st("/task-creators/add_existing_questions/both-types",
	      test_add_existing_questions_both_types);

  return g_test_run() == 0;
}

static bool should_only_run_tests(int *argc_p, char **argv_p[]){
  GOptionContext *context = g_option_context_new("");

  g_option_context_set_help_enabled(context, FALSE);
  g_option_context_set_ignore_unknown_options(context, TRUE);

  gboolean run_tests = FALSE;
  GOptionEntry entries[] = {
    { "test", 0, 0, G_OPTION_ARG_NONE,
      &run_tests, "Run tests", NULL },
    { NULL }
  };
  g_option_context_add_main_entries(context, entries, NULL);

  GError *error = NULL;

  if(g_option_context_parse(context, argc_p, argv_p, &error) != TRUE){
    g_option_context_free(context);
    g_error("Failed to parse options: %s", error->message);
  }

  g_option_context_free(context);
  return run_tests != FALSE;
}
