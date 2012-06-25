/*
 * ldpreloadhook - a quick open/close/ioctl/read/write syscall hooker
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
 * 1) Configure "spy_file" in the code below
 * 2) Compile:
 *   gcc -fPIC -c -o hook.o hook.c
 *   gcc -shared -o hook.so hook.o -ldl
 * 3) Usage:
 *   LD_PRELOAD="./hook.so" command
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>

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

static const char *data_w_file = "/tmp/write_data.bin";
static const char *data_r_file = "/tmp/read_data.bin"; 
static const char *spy_file = "/dev/serio_raw0";

int open (const char *pathname, int flags, ...){

	static int (*func_open) (const char *, int, mode_t) = NULL;
	va_list args;
	mode_t mode;
	int fd;

	if (!func_open)
		func_open = (int (*) (const char *, int, mode_t)) dlsym (REAL_LIBC, "open");

	va_start (args, flags);
	mode = va_arg (args, mode_t);
	va_end (args);

	if (strcmp (pathname, spy_file)){	
		fd = func_open (pathname, flags, mode);
		return fd;
	}

	data_w_fd = func_open (data_w_file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	data_r_fd = func_open (data_r_file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	hook_fd = func_open (pathname, flags, mode);

	DPRINTF ("HOOK: opened file %s (fd=%d)\n", pathname, hook_fd);

	return hook_fd;
}

int close (int fd){	

	static int (*func_close) (int) = NULL;
	int retval = 0;

	if (fd == hook_fd)
		DPRINTF ("HOOK: closed file %s (fd=%d)\n", spy_file, fd);

	if (! func_close)
		func_close = (int (*) (int)) dlsym (REAL_LIBC, "close");
		
	retval = func_close (fd);
	return retval;
}

int ioctl (int fd, request_t request, ...){	

	static int (*func_ioctl) (int, request_t, void *) = NULL;
	va_list args;
	void *argp;

	if (! func_ioctl)
		func_ioctl = (int (*) (int, request_t, void *)) dlsym (REAL_LIBC, "ioctl");
	va_start (args, request);
	argp = va_arg (args, void *);
	va_end (args);

	if (fd != hook_fd)
		return func_ioctl (fd, request, argp);
	else
		DPRINTF ("HOOK: ioctl (fd=%d)\n", fd);

	/* Capture the ioctl() calls */
	return func_ioctl (hook_fd, request, argp);
}

ssize_t read (int fd, void *buf, size_t count){	

	static ssize_t (*func_read) (int, const void*, size_t) = NULL;
	static ssize_t (*func_write) (int, const void*, size_t) = NULL;

	ssize_t retval = 0;
	if (! func_read)
		func_read = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "read");
	if (! func_write)
		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

	if (fd != hook_fd)
		return func_read (fd, buf, count);
	else
		DPRINTF ("HOOK: read %d bytes from file %s (fd=%d)\n", count, spy_file, fd);

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

	if (! func_write)
		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

	if (fd != hook_fd)
		return func_write (fd, buf, count);

	DPRINTF ("HOOK: write %d bytes to file %s (fd=%d)\n", count, spy_file, fd);

	func_write (hook_fd, buf, count);
	retval = func_write (data_w_fd, buf, count);

	return retval;
}
