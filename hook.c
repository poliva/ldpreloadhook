/*
 * ldpreloadhook - a quick open/close/ioctl/read/write/free/strcmp/strncmp symbol hooker
 * Copyright (C) 2012-2013 Pau Oliva Fora <pof@eslack.org>
 *
 * Based on vsound 0.6 source code:
 *   Copyright (C) 2004 Nathan Chantrell <nsc@zorg.org>
 *   Copyright (C) 2003 Richard Taylor <r.taylor@bcs.org.uk>
 *   Copyright (C) 2000,2001 Erik de Castro Lopo <erikd@zip.com.au>
 *   Copyright (C) 1999 James Henstridge <james@daa.com.au>
 * Based on esddsp utility that is part of esound:
 *   Copyright (C) 1998, 1999 Manish Singh <yosh@gimp.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * 1) Compile:
 *   gcc -fPIC -c -o hook.o hook.c
 *   gcc -shared -o hook.so hook.o -ldl
 * 2) Usage:
 *   LD_PRELOAD="./hook.so" command
 *   LD_PRELOAD="./hook.so" SPYFILE="/file/to/spy" command
 *   LD_PRELOAD="./hook.so" SPYFILE="/file/to/spy" DELIMITER="***" command
 * to spy the content of buffers free'd by free(), set the environment
 * variable SPYFREE, for example:
 *   LD_PRELOAD="./hook.so" SPYFREE=1 command
 * to spy the strings compared using strcmp(), set the environment
 * variable SPYSTR, for example:
 *   LD_PRELOAD="./hook.so" SPYSTR=1 command
 * to spy memcpy() buffers set the env variable SPYMEM
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <signal.h>

int g_obvio=0;
#define DPRINTF(format, args...)	if (!g_obvio) { g_obvio=1; fprintf(stderr, format, ## args); g_obvio=0; }

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

#define REAL_LIBC RTLD_NEXT

#ifdef __FreeBSD__
typedef unsigned long request_t;
#else
typedef int request_t;
#endif

typedef void (*sighandler_t)(int);

static int data_w_fd = -1, hook_fd = -1, data_r_fd = -1;

#ifdef __ANDROID__
static const char *data_w_file = "/data/local/tmp/write_data.bin";
static const char *data_r_file = "/data/local/tmp/read_data.bin";
#else
static const char *data_w_file = "/tmp/write_data.bin";
static const char *data_r_file = "/tmp/read_data.bin"; 
#endif

static void _libhook_init() __attribute__ ((constructor));
static void _libhook_init() {   
	/* causes segfault on some android, uncomment if you need it */
	//unsetenv("LD_PRELOAD");
	printf("[] Hooking!\n");
}

ssize_t write (int fd, const void *buf, size_t count);
void free (void *buf);

int open (const char *pathname, int flags, ...){

	static int (*func_open) (const char *, int, mode_t) = NULL;
	va_list args;
	mode_t mode;
	int fd;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (!func_open)
		func_open = (int (*) (const char *, int, mode_t)) dlsym (REAL_LIBC, "open");

	va_start (args, flags);
	mode = va_arg (args, int);
	va_end (args);

	if (strcmp (pathname, spy_file)){	
		fd = func_open (pathname, flags, mode);
		DPRINTF ("HOOK: opened file %s (fd=%d)\n", pathname, fd);
		return fd;
	}

	data_w_fd = func_open (data_w_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	data_r_fd = func_open (data_r_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	hook_fd = func_open (pathname, flags, mode);

	/* write the delimiter each time we open the files */
	if (getenv("DELIMITER") != NULL) {
		write (data_r_fd, getenv("DELIMITER"), strlen(getenv("DELIMITER")));
		write (data_w_fd, getenv("DELIMITER"), strlen(getenv("DELIMITER")));
	}

	DPRINTF ("HOOK: opened hooked file %s (fd=%d)\n", pathname, hook_fd);

	return hook_fd;
}

int strcmp(const char *s1, const char *s2) {

	static int (*func_strcmp) (const char *, const char *) = NULL;
	int retval = 0;

	if (! func_strcmp)
		func_strcmp = (int (*) (const char*, const char*)) dlsym (REAL_LIBC, "strcmp");

	if (getenv("SPYSTR") != NULL) {
		DPRINTF ("HOOK: strcmp( \"%s\" , \"%s\" )\n", s1, s2);
	}

	retval = func_strcmp (s1, s2);
	return retval;

}

int strncmp(const char *s1, const char *s2, size_t n) {

	static int (*func_strncmp) (const char *, const char *, size_t) = NULL;
	int retval = 0;

	if (! func_strncmp)
		func_strncmp = (int (*) (const char*, const char*, size_t)) dlsym (REAL_LIBC, "strncmp");

	if (getenv("SPYSTR") != NULL) {
		DPRINTF ("HOOK: strncmp( \"%s\" , \"%s\" , %zd )\n", s1, s2, n);
	}

	retval = func_strncmp (s1, s2, n);
	return retval;

}

int close (int fd){	

	static int (*func_close) (int) = NULL;
	int retval = 0;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (! func_close)
		func_close = (int (*) (int)) dlsym (REAL_LIBC, "close");

	if (fd == hook_fd) {
		DPRINTF ("HOOK: closed hooked file %s (fd=%d)\n", spy_file, fd);
	} else {
		DPRINTF ("HOOK: closed file descriptor (fd=%d)\n", fd);
	}
		
	retval = func_close (fd);
	return retval;
}

int ioctl (int fd, request_t request, ...){	

	static int (*func_ioctl) (int, request_t, void *) = NULL;
	va_list args;
	void *argp;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (! func_ioctl)
		func_ioctl = (int (*) (int, request_t, void *)) dlsym (REAL_LIBC, "ioctl");
	va_start (args, request);
	argp = va_arg (args, void *);
	va_end (args);

	if (fd != hook_fd) {
		DPRINTF ("HOOK: ioctl (fd=%d, request=%p, argp=%p [%02X])\n", fd, request, argp);
		return func_ioctl (fd, request, argp);
	} 

	DPRINTF ("HOOK: ioctl on hooked file %s (fd=%d)\n", spy_file, fd);

	/* Capture the ioctl() calls */
	return func_ioctl (hook_fd, request, argp);
}

ssize_t read (int fd, void *buf, size_t count){	

	static ssize_t (*func_read) (int, const void*, size_t) = NULL;
	static ssize_t (*func_write) (int, const void*, size_t) = NULL;

	ssize_t retval = 0;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (! func_read)
		func_read = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "read");
	if (! func_write)
		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

	if (fd != hook_fd) {
		DPRINTF ("HOOK: read %zd bytes from file descriptor (fd=%d)\n", count, fd);
		return func_read (fd, buf, count);
	}

	DPRINTF ("HOOK: read %zd bytes from hooked file %s (fd=%d)\n", count, spy_file, fd);

	retval = func_read(fd, buf, count);

	char *buf2 = calloc(retval, sizeof(char));
	memcpy(buf2, buf, retval);

	func_write (data_r_fd, buf2, retval);
	free(buf2);

	return retval;
}

ssize_t write (int fd, const void *buf, size_t count){	

	static ssize_t (*func_write) (int, const void*, size_t) = NULL;
	ssize_t retval = 0;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (! func_write)
		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

	if (fd != hook_fd) {
		DPRINTF ("HOOK: write %zd bytes to file descriptor (fd=%d)\n", count, fd);
		return func_write (fd, buf, count);
	}

	DPRINTF ("HOOK: write %zd bytes to hooked file %s (fd=%d)\n", count, spy_file, fd);

	func_write (hook_fd, buf, count);
	retval = func_write (data_w_fd, buf, count);

	return retval;
}

void free (void *ptr){	

	static void (*func_free) (void*) = NULL;

	char *tmp = ptr;
	char tmp_buf[1025] = {0};
	size_t total = 0;

	if (! func_free) 
		func_free = (void (*) (void*)) dlsym (REAL_LIBC, "free");

	if (getenv("SPYFREE") != NULL) {
		if (ptr != NULL) {

			while (*tmp != '\0') {
				tmp_buf[total] = *tmp;
				total++;
				if (total == 1024)
					break;
				tmp++;
			}

			if (strlen(tmp_buf) != 0) 
				DPRINTF("HOOK: free( ptr[%zd]=%s )\n",strlen(tmp_buf), tmp_buf);
		}
	}

	func_free (ptr);
}

void *memcpy(void *dest, const void *src, size_t n) {

	DPRINTF("HOOK: memcpy( dest=%p , src=%p, size=%zd )\n", dest, src, n);

	static void (*func_memcpy) (void*, const void *, size_t) = NULL;
	if (! func_memcpy)
		func_memcpy = (void (*) (void*, const void *, size_t)) dlsym (REAL_LIBC, "memcpy");

	func_memcpy(dest,src,n);

	if (getenv("SPYMEM") != NULL) {

		char *tmp = dest;
		char tmp_buf[1025] = {0};
		size_t total = 0;

		DPRINTF("      memcpy buffer: ");
		while (total < n) {
			tmp_buf[total] = *tmp;
			DPRINTF("%02X ", tmp_buf[total]);
			total++;
			if (total == 1024)
				break;
			tmp++;
		}

		DPRINTF("\n");
		DPRINTF("      memcpy str: [%zd]=%s )\n",strlen(tmp_buf), tmp_buf);
	}
}

int puts(const char *s) {

	static int (*func_puts) (const char *) = NULL;
	int retval = 0;

	if (! func_puts)
		func_puts = (int (*) (const char*)) dlsym (REAL_LIBC, "puts");

	DPRINTF ("HOOK: puts( \"%s\" )\n", s);

	retval = func_puts (s);
	return retval;
}

uid_t getuid(void) {

	static uid_t (*func_getuid) (void) = NULL;
	if (!func_getuid)
		func_getuid = (uid_t (*) (void)) dlsym (REAL_LIBC, "getuid");

	uid_t retval = func_getuid();
	DPRINTF("HOOK: getuid() returned %d\n", retval);

	return retval;
}

int system(const char *command) {

	static int (*func_system) (const char *) = NULL;
	int retval = 0;

	if (! func_system)
		func_system = (int (*) (const char*)) dlsym (REAL_LIBC, "system");

	retval = func_system (command);

	DPRINTF ("HOOK: system( \"%s\" ) returned %d\n", command, retval);

	return retval;

}

void *malloc(size_t size) {

	static void (*func_malloc) (size_t) = NULL;
	if (! func_malloc)
		func_malloc = (void (*) (size_t)) dlsym (REAL_LIBC, "malloc");

	DPRINTF("HOOK: malloc( size=%zd )\n", size);
	func_malloc(size);
}


void abort(void) {

	static void (*func_abort) (void) = NULL;
	if (! func_abort)
		func_abort = (void (*) (void)) dlsym (REAL_LIBC, "abort");
	DPRINTF("HOOK: abort()\n");
	func_abort();
}

int chmod(const char *path, mode_t mode) {

	static int (*func_chmod) (const char *, mode_t) = NULL;
	int retval = 0;

	if (! func_chmod)
		func_chmod = (int (*) (const char*, mode_t)) dlsym (REAL_LIBC, "chmod");

	retval = func_chmod (path, mode);

	DPRINTF ("HOOK: chmod( \"%s\", mode=%o ) returned %d\n", path, mode, retval);

	return retval;

}

sighandler_t bsd_signal(int signum, sighandler_t handler) {

	static sighandler_t (*func_bsd_signal) (int, sighandler_t) = NULL;

	if (! func_bsd_signal)
		func_bsd_signal = (sighandler_t (*) (int, sighandler_t)) dlsym (REAL_LIBC, "bsd_signal");

	sighandler_t retval = func_bsd_signal (signum, handler);

	DPRINTF ("HOOK: bsd_signal \"%d\" \n", signum);
	return retval;

}

int unlink(const char *pathname) {

	static int (*func_unlink) (const char *) = NULL;
	int retval = 0;

	if (! func_unlink)
		func_unlink = (int (*) (const char*)) dlsym (REAL_LIBC, "unlink");

	retval = func_unlink (pathname);

	DPRINTF ("HOOK: unlink( \"%s\" ) returned %d\n", pathname, retval);

	return retval;

}

pid_t fork(void) {

	static pid_t (*func_fork) (void) = NULL;
	if (!func_fork)
		func_fork = (pid_t (*) (void)) dlsym (REAL_LIBC, "fork");

	pid_t retval = func_fork();
	DPRINTF("HOOK: fork() returned %d\n", retval);

	return retval;
}

void srand48(long int seedval) {

	static void (*func_srand48) (long int) = NULL;
	if (! func_srand48)
		func_srand48 = (void (*) (long int)) dlsym (REAL_LIBC, "srand48");

	DPRINTF("HOOK: srand48( size=%ld )\n", seedval);
	func_srand48(seedval);

}

#if 0
void *memset(void *s, int c, size_t n) {
	DPRINTF("HOOK: memset()\n");

	static void (*func_memset) (void*, int, size_t) = NULL;
	if (! func_memset)
		func_memset = (void (*) (void*, int, size_t)) dlsym (REAL_LIBC, "memset");

	DPRINTF("HOOK: memset( s=%p , c=%d, n=%zd )\n", s, c, n);
	func_memset(s,c,n);
}
# endif

time_t time(time_t *t) {

	static time_t (*func_time) (time_t *) = NULL;
	time_t retval = 0;

	if (! func_time)
		func_time = (time_t (*) (time_t *)) dlsym (REAL_LIBC, "time");

	DPRINTF ("HOOK: time( \"%d\" )\n", t);
	retval = func_time (t);
	return retval;
}


long int lrand48(void) {

	static long int (*func_lrand48) (void) = NULL;
	if (! func_lrand48)
		func_lrand48 = (long int (*) (void)) dlsym (REAL_LIBC, "lrand48");

	long int retval = func_lrand48();
	DPRINTF("HOOK: lrand48() returned %ld\n", retval);

	return retval;
}

size_t strlen(const char *s) {

	static size_t (*func_strlen) (const char *) = NULL;
	int retval = 0;

	if (! func_strlen)
		func_strlen = (size_t (*) (const char*)) dlsym (REAL_LIBC, "strlen");

	retval = func_strlen (s);

	static int (*func_strncmp) (const char *, const char *, size_t) = NULL;
        if (! func_strncmp)
                func_strncmp = (int (*) (const char*, const char*, size_t)) dlsym (REAL_LIBC, "strncmp");

	if (func_strncmp (s, "spyfile", 7) != 0){
		DPRINTF ("HOOK: strlen( \"%s\" ) returned %d\n", s, retval);
	}

	return retval;
}

int raise(int sig) {

	static int (*func_raise) (int) = NULL;
	int retval = 0;

	if (! func_raise)
		func_raise = (int (*) (int)) dlsym (REAL_LIBC, "raise");

	retval = func_raise (sig);
	DPRINTF ("HOOK: raise( \"%d\" ) returned %d\n", sig, retval);

	return retval;
}
