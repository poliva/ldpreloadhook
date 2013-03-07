/*
 * ldpreloadhook - a quick open/close/ioctl/read/write/free symbol hooker
 * Copyright (C) 2012 Pau Oliva Fora <pof@eslack.org>
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
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DPRINTF(format, args...)	fprintf(stderr, format, ## args)

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

#define REAL_LIBC RTLD_NEXT

#ifdef __FreeBSD__
typedef unsigned long request_t;
#else
typedef int request_t;
#endif

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
	unsetenv("LD_PRELOAD");
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

	DPRINTF ("HOOK: strcmp( %s , %s )\n", s1, s2);

	retval = func_strcmp (s1, s2);
	return retval;

}

int close (int fd){	

	static int (*func_close) (int) = NULL;
	int retval = 0;

	setenv("SPYFILE", "spyfile", 0);
	char *spy_file = getenv("SPYFILE");

	if (! func_close)
		func_close = (int (*) (int)) dlsym (REAL_LIBC, "close");

	if (fd == hook_fd)
		DPRINTF ("HOOK: closed hooked file %s (fd=%d)\n", spy_file, fd);
	else
		DPRINTF ("HOOK: closed file descriptor (fd=%d)\n", fd);
		
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
		DPRINTF ("HOOK: ioctl (fd=%d)\n", fd);
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
