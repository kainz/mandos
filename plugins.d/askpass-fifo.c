#define _GNU_SOURCE		/* TEMP_FAILURE_RETRY() */
#include <sys/types.h>		/* ssize_t */
#include <sys/stat.h>		/* mkfifo(), S_IRUSR, S_IWUSR */
#include <iso646.h>		/* and */
#include <errno.h>		/* errno, EEXIST */
#include <stdio.h>		/* perror() */
#include <stdlib.h>		/* EXIT_FAILURE, NULL, size_t, free(), 
				   realloc(), EXIT_SUCCESS */
#include <fcntl.h>		/* open(), O_RDONLY */
#include <unistd.h>		/* read(), close(), write(),
				   STDOUT_FILENO */


int main(__attribute__((unused))int argc,
	 __attribute__((unused))char **argv){
  int ret = 0;
  ssize_t sret;
  
  /* Create FIFO */
  const char passfifo[] = "/lib/cryptsetup/passfifo";
  ret = TEMP_FAILURE_RETRY(mkfifo(passfifo, S_IRUSR | S_IWUSR));
  if(ret == -1 and errno != EEXIST){
    perror("mkfifo");
    return EXIT_FAILURE;
  }
  
  /* Open FIFO */
  int fifo_fd = TEMP_FAILURE_RETRY(open(passfifo, O_RDONLY));
  if(fifo_fd == -1){
    perror("open");
    return EXIT_FAILURE;
  }
  
  /* Read from FIFO */
  char *buf = NULL;
  size_t buf_len = 0;
  {
    size_t buf_allocated = 0;
    const size_t blocksize = 1024;
    do{
      if(buf_len + blocksize > buf_allocated){
	char *tmp = realloc(buf, buf_allocated + blocksize);
	if(tmp == NULL){
	  perror("realloc");
	  free(buf);
	  return EXIT_FAILURE;
	}
	buf = tmp;
	buf_allocated += blocksize;
      }
      sret = TEMP_FAILURE_RETRY(read(fifo_fd, buf + buf_len,
				     buf_allocated - buf_len));
      if(sret == -1){
	perror("read");
	free(buf);
	return EXIT_FAILURE;
      }
      buf_len += (size_t)sret;
    }while(sret != 0);
  }
  
  /* Close FIFO */
  TEMP_FAILURE_RETRY(close(fifo_fd));
  
  /* Print password to stdout */
  size_t written = 0;
  while(written < buf_len){
    sret = TEMP_FAILURE_RETRY(write(STDOUT_FILENO, buf + written,
				    buf_len - written));
    if(sret == -1){
      perror("write");
      free(buf);
      return EXIT_FAILURE;
    }
    written += (size_t)sret;
  }
  free(buf);
  
  return EXIT_SUCCESS;
}
