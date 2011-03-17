/*  -*- coding: utf-8 -*- */
/*
 * Askpass-FIFO - Read a password from a FIFO and output it
 * 
 * Copyright © 2008-2011 Teddy Hogeborn
 * Copyright © 2008-2011 Björn Påhlsson
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
#include <sys/types.h>		/* ssize_t */
#include <sys/stat.h>		/* mkfifo(), S_IRUSR, S_IWUSR */
#include <iso646.h>		/* and */
#include <errno.h>		/* errno, EACCES, ENOTDIR, ELOOP,
				   ENAMETOOLONG, ENOSPC, EROFS,
				   ENOENT, EEXIST, EFAULT, EMFILE,
				   ENFILE, ENOMEM, EBADF, EINVAL, EIO,
				   EISDIR, EFBIG */
#include <error.h>		/* error() */
#include <stdlib.h>		/* EXIT_FAILURE, NULL, size_t, free(),
				   realloc(), EXIT_SUCCESS */
#include <fcntl.h>		/* open(), O_RDONLY */
#include <unistd.h>		/* read(), close(), write(),
				   STDOUT_FILENO */
#include <sysexits.h>		/* EX_OSERR, EX_OSFILE,
				   EX_UNAVAILABLE, EX_IOERR */


int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  int ret = 0;
  ssize_t sret;
  
  /* Create FIFO */
  const char passfifo[] = "/lib/cryptsetup/passfifo";
  ret = mkfifo(passfifo, S_IRUSR | S_IWUSR);
  if(ret == -1){
    int e = errno;
    switch(e){
    case EACCES:
    case ENOTDIR:
    case ELOOP:
      error(EX_OSFILE, errno, "mkfifo");
    case ENAMETOOLONG:
    case ENOSPC:
    case EROFS:
    default:
      error(EX_OSERR, errno, "mkfifo");
    case ENOENT:
      /* no "/lib/cryptsetup"? */
      error(EX_UNAVAILABLE, errno, "mkfifo");
    case EEXIST:
      break;			/* not an error */
    }
  }
  
  /* Open FIFO */
  int fifo_fd = open(passfifo, O_RDONLY);
  if(fifo_fd == -1){
    int e = errno;
    error(0, errno, "open");
    switch(e){
    case EACCES:
    case ENOENT:
    case EFAULT:
      return EX_UNAVAILABLE;
    case ENAMETOOLONG:
    case EMFILE:
    case ENFILE:
    case ENOMEM:
    default:
      return EX_OSERR;
    case ENOTDIR:
    case ELOOP:
      return EX_OSFILE;
    }
  }
  
  /* Read from FIFO */
  char *buf = NULL;
  size_t buf_len = 0;
  {
    size_t buf_allocated = 0;
    const size_t blocksize = 1024;
    do {
      if(buf_len + blocksize > buf_allocated){
	char *tmp = realloc(buf, buf_allocated + blocksize);
	if(tmp == NULL){
	  error(0, errno, "realloc");
	  free(buf);
	  return EX_OSERR;
	}
	buf = tmp;
	buf_allocated += blocksize;
      }
      sret = read(fifo_fd, buf + buf_len, buf_allocated - buf_len);
      if(sret == -1){
	int e = errno;
	free(buf);
	errno = e;
	error(0, errno, "read");
	switch(e){
	case EBADF:
	case EFAULT:
	case EINVAL:
	default:
	  return EX_OSERR;
	case EIO:
	  return EX_IOERR;
	case EISDIR:
	  return EX_UNAVAILABLE;
	}
      }
      buf_len += (size_t)sret;
    } while(sret != 0);
  }
  
  /* Close FIFO */
  close(fifo_fd);
  
  /* Print password to stdout */
  size_t written = 0;
  while(written < buf_len){
    sret = write(STDOUT_FILENO, buf + written, buf_len - written);
    if(sret == -1){
      int e = errno;
      free(buf);
      errno = e;
      error(0, errno, "write");
      switch(e){
      case EBADF:
      case EFAULT:
      case EINVAL:
	return EX_OSFILE;
      case EFBIG:
      case EIO:
      case ENOSPC:
      default:
	return EX_IOERR;
      }
    }
    written += (size_t)sret;
  }
  free(buf);
  
  ret = close(STDOUT_FILENO);
  if(ret == -1){
    int e = errno;
    error(0, errno, "close");
    switch(e){
    case EBADF:
      return EX_OSFILE;
    case EIO:
    default:
      return EX_IOERR;
    }
  }
  return EXIT_SUCCESS;
}
