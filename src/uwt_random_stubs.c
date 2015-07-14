/*
 * Copyright (c) 2015 Andreas Hauptmann
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Parts of this code are inspired by openssl /libressl
 * Thanks to:
 * - Theo de Raadt
 * - Bob Beck
 * - Eric Young
 */

#include "config.h"
#ifndef _WIN32
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_RND_H
#include <sys/rnd.h>
#endif
#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#ifdef HAVE_LINUX_RANDOM_H
#include <linux/random.h>
#endif
#ifdef HAVE_LINUX_SYSCTL_H
#include <linux/sysctl.h>
#endif
#endif  /* _WIN32 */

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#include <string.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>

#define CAML_NAME_SPACE 1
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/signals.h>
#include <caml/bigarray.h>
#include <caml/unixsupport.h>

#ifdef _WIN32
#include <Wincrypt.h>
#endif

#include <uwt-worker.h>
#include <uwt-error.h>

#include "macros.h"

#ifndef _WIN32
static int
sanity_check(const unsigned char *buf, size_t len)
{
  if ( len < 2 ){
    return 0;
  }
  else {
    unsigned char set = 0;
    size_t  i;
    for ( i = 0; i < len; ++i ){
      set |= buf[i];
    }
    if (set == 0){
      return -1;
    }
    else {
      return 0;
    }
  }
}

static int
from_device(unsigned char *buf,
            size_t len,
            const char *device,
            int * back_fd,
            int sun_check)
{
  struct stat st;
  size_t i;
  int fd, flags;
#if defined(__linux__) && defined(RNDGETENTCNT)
  int cnt;
#endif
  int erg;
  (void)sun_check;
  flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
#ifdef O_BINARY
  flags |= O_BINARY;
#endif
#ifdef O_NOCTTY
  flags |= O_NOCTTY;
#endif
  flags |= O_NONBLOCK;
  do {
    fd = open(device, flags, 0);
  } while ( fd == -1 && errno == EINTR );
  if ( fd == -1 ){
    DEBUG_PF("open:%d,%s\n",errno,strerror(errno));
    return (-1);
  }
#if !defined(O_CLOEXEC) && defined(FD_CLOEXEC)
  erg = fcntl(fd, F_GETFD);
  if ( erg == -1 ){
    close(fd);
    return (-1);
  }
  erg = fcntl(fd, F_SETFD, erg | FD_CLOEXEC);
  if ( erg == -1 ){
    close(fd);
    return (-1);
  }
#endif
  do {
    erg = fstat(fd, &st);
  } while ( erg == -1 && errno == EINTR );
  if ( erg == -1 || !S_ISCHR(st.st_mode) ){
    close(fd);
    return (-1);
  }
#if defined(__sun) && defined(__SVR4)
  if ( sun_check && strcmp(st.st_fstype, "devfs") != 0 ){
    close(fd);
    return (-1);
  }
#endif
#if defined(__linux__) && defined(RNDGETENTCNT)
  if ( ioctl(fd, RNDGETENTCNT, &cnt) == -1 ){
    close(fd);
    return (-1);
  }
#endif
  i = 0;
  while ( i < len ){
    size_t to_read = len - i;
    ssize_t r ;
    do {
      r = read(fd, buf + i, to_read);
    } while ( r == -1 && (errno == EINTR || errno == EAGAIN) );
    if ( r < 0 ){
      close(fd);
      return (-1);
    }
    i += r;
  }
  erg = sanity_check(buf,len);
  if ( back_fd == NULL || erg != 0 ){
    close(fd);
  }
  else {
    *back_fd = fd;
  }
  return erg;
}
#endif

#if defined(HAVE_GETRANDOM_INTERFACE) && defined(HAVE_GETRANDOM_SYSCALL)
static int
linux_getrandom(void *buf, size_t len, int flag)
{
  long ret;
  do {
    ret = syscall(SYS_getrandom, buf, len, flag);
  } while ( ret == -1 && errno == EINTR );
  if ( ret == -1 && errno == EAGAIN ){
    return 1;
  }
  if ( ret < 0 || (size_t)ret != len ){
    return (-1);
  }
  return (0);
}
#endif

#if defined(__linux__) && defined(SYS__sysctl)
static int
linux_sysctl(unsigned char *buf, size_t len)
{
#if !defined(CTL_KERN) || !defined(KERN_RANDOM) || !defined(RANDOM_UUID)
  (void)buf;
  (void)len;
  return -1;
#else
  static int mib[] = { CTL_KERN, KERN_RANDOM, RANDOM_UUID };
  size_t i = 0;
  while ( i < len ){
    size_t to_read = len - i ;
    to_read = to_read > 16 ? 16 : to_read;
    struct __sysctl_args args = {
      .name = mib,
      .nlen = 3,
      .oldval = buf + i,
      .oldlenp = &to_read,
    };
    long r;
    do {
      syscall(SYS__sysctl, &args);
    } while ( r == -1 && errno == EINTR );
    if ( r != 0 ){
      return (-1);
    }
    i += to_read;
  }
  return 0;
#endif
}
#endif /* defined(__linux__) && defined(SYS__sysctl) */

#if (defined(__FreeBSD__) || defined(__NetBSD__)) && (defined(CTL_KERN) && defined(KERN_ARND))
static int
bsd_sysctl(unsigned char *buf, size_t size)
{
  int mib[2];
  size_t len, done;

  mib[0] = CTL_KERN;
  mib[1] = KERN_ARND;
  done = 0;
  do {
    int r;
    len = size;
    do {
      r = sysctl(mib, 2, buf, &len, NULL, 0);
    } while ( r < 0 && errno == EINTR );
    if ( r < 0 ){
      return (-1);
    }
    done += len;
    buf += len;
    size = len > size ? 0 : size - len;
  } while ( size > 0 );
  return (0);
}
#endif

#if defined(__OpenBSD__) && defined(HAVE_GETENTROPY)
static int
bsd_sysctl(unsigned char *buf, size_t len)
{
  unsigned char* p = buf;
  while ( len ){
    int read = len > 256 ? 256 : len;
    if ( getentropy(p,read) == -1 ){
      return (-1);
    }
    p += read;
    len -= read;
  }
  return 0;
}
#endif

#define Ba_buf_val(x)  ((unsigned char*)Caml_ba_data_val(x))
CAMLextern value
uwt_random_get(value tok, value obytes, value ooffset, value olen);

CAMLprim value
uwt_random_get(value tok, value obytes, value oofset, value olen)
{
  int r = -1;
  unsigned char * cstr ;
  size_t len = Long_val(olen);
  if ( Tag_val(obytes) == 0 ){
    cstr = (unsigned char *)String_val(Field(obytes,0));
  }
  else {
    cstr = Ba_buf_val(Field(obytes,0));
  }
  cstr += Long_val(oofset);

  if ( Is_long(tok) ){
    switch (Long_val(tok)){
    case 0:
#if defined(__linux__)
#if defined(HAVE_GETRANDOM_INTERFACE) && defined(HAVE_GETRANDOM_SYSCALL)
      r = linux_getrandom(cstr,len,0);
      if ( r == -1 ){
        DEBUG_PF("%d:%s",r,strerror(errno));
      }
#endif
#elif defined(__OpenBSD__) && defined(HAVE_GETENTROPY)
      r = bsd_sysctl(cstr,len);
#elif (defined(__FreeBSD__) || defined(__NetBSD__)) && (defined(CTL_KERN) && defined(KERN_ARND))
      r = bsd_sysctl(cstr,len);
#else
      DEBUG_PF("invalid case in uwt_random_get");
#endif
      break;
    case 1:
#if defined(__linux__)
      r = linux_sysctl(cstr,len);
#else
      DEBUG_PF("invalid case in uwt_random_get");
#endif
      break;
    default:
      DEBUG_PF("invalid case in uwt_random_get");
    }
  }
  else {
#ifndef _WIN32
    DEBUG_PF("invalid case in uwt_random_get");
#else
    HCRYPTPROV hCryptProv;
    hCryptProv = (HCRYPTPROV) Nativeint_val(tok);
    if ( hCryptProv != 0 ){
      r = CryptGenRandom(hCryptProv, len, cstr);
      r = r == 0 ? -1 : 0;
    }
#endif
  }
  return (Val_long(r == 0));
}

CAMLextern value
uwt_random_close(value tok);

CAMLprim value
uwt_random_close(value tok)
{
#ifdef _WIN32
  HCRYPTPROV hCryptProv;
  hCryptProv = (HCRYPTPROV) Nativeint_val(tok);
  if ( hCryptProv != 0 ){
    Nativeint_val(tok) = 0;
    CryptReleaseContext(hCryptProv, 0);
  }
#else
  (void) tok;
#endif
  return Val_unit;
}

CAMLextern value
uwt_random_init_nonblock(value unit);

CAMLprim value
uwt_random_init_nonblock(value unit)
{
  (void) unit;
#if defined(__linux__)
#if defined(HAVE_GETRANDOM_INTERFACE) && defined(HAVE_GETRANDOM_SYSCALL)
  unsigned char testbuf[2];
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 1
#endif
  int x = linux_getrandom(testbuf,2,GRND_NONBLOCK);
  if ( x == 0 ){
    DEBUG_PF("linux ok");
    value v = caml_alloc_small(1,0);
    Field(v,0) = Val_long(0);
    return v;
  }
  else {
    if ( x == 1 ){
      DEBUG_PF("linux would block");
      return Val_long(1);
    }
  }
  DEBUG_PF("linux failed");
#else
  DEBUG_PF("urandom only");
#endif
  return (Val_long(0));

#elif (defined(__OpenBSD__) && defined(HAVE_GETENTROPY)) || ((defined(__FreeBSD__) || defined(__NetBSD__)) && (defined(CTL_KERN) && defined(KERN_ARND)))
  unsigned char testbuf[2];
  if ( bsd_sysctl(testbuf,2) == 0 ){
    DEBUG_PF("bsd ok");
    value v = caml_alloc_small(1,0);
    Field(v,0) = Val_long(0);
    return v;
  }
  DEBUG_PF("bsd failed");
  return (Val_long(0));
#elif defined(_WIN32)
  CAMLparam0();
  CAMLlocal2(ret,cntx);
  HCRYPTPROV hCryptProv;
  cntx = caml_copy_nativeint(0);
  ret = caml_alloc(1,0);
  if ( CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT) ||
       CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET) ){
    Nativeint_val(cntx) = hCryptProv;
    Store_field(ret,0,cntx);
    DEBUG_PF("windows ok");
  }
  else {
    ret = Val_long(0);
    DEBUG_PF("windows failed");
  }
  CAMLreturn(ret);
#else
  DEBUG_PF("urandom only");
  return (Val_long(0));
#endif
}

CAMLextern value
uwt_random_uwt_init(value o_user, value o_uwt);

#ifndef _WIN32
static void
uwt_random_worker(uv_work_t * req)
{
  enum random_source {
    UWT_RANDOM_URANDOM_DEVICE = 1,
    UWT_RANDOM_BACKUP_SYSCALL = 2,
    UWT_RANDOM_ERROR = 3
  };
  enum random_source to_use = UWT_RANDOM_ERROR;
  struct worker_params * w = req->data;
  unsigned char testbuf[32];
  int fd = -1;
  int r;
#if defined(__linux__)
  memset(testbuf,0,sizeof testbuf);
  r = from_device(testbuf,sizeof testbuf,"/dev/urandom",&fd,0);
  if ( r == 0 ){
    DEBUG_PF("linux /dev/urandom ok");
    to_use = UWT_RANDOM_URANDOM_DEVICE;
  }
  else {
    DEBUG_PF("linux /dev/urandom failed");
#if defined(SYS__sysctl)
    memset(testbuf,0,sizeof testbuf);
    r = linux_sysctl(testbuf,sizeof testbuf);
    if ( r == 0 ){
      r = sanity_check(testbuf,sizeof testbuf);
    }
    if ( r == 0 ){
      DEBUG_PF("linux sysctl ok");
      to_use = UWT_RANDOM_BACKUP_SYSCALL;
    }
    else {
      DEBUG_PF("linux sysctl failed");
    }
#endif
  }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  memset(testbuf,0,sizeof testbuf);
  r = from_device(testbuf,sizeof testbuf,"/dev/urandom",&fd,0);
  if ( r == 0 ){
    DEBUG_PF("bsd /dev/urandom ok");
    to_use = UWT_RANDOM_URANDOM_DEVICE;
  }
  else {
#ifdef __FreeBSD__
    /* freebsd symlinks /dev/urandom to /dev/random -
       and /dev/random doesn't block */
    memset(testbuf,0,sizeof testbuf);
    r = from_device(testbuf,sizeof testbuf,"/dev/random",&fd,0);
    if ( r == 0 ){
      to_use = UWT_RANDOM_URANDOM_DEVICE;
      DEBUG_PF("freebsd /dev/random ok");
    }
    else {
      DEBUG_PF("freebsd /dev/*random failed");
    }
#else
    DEBUG_PF("bsd /dev/urandom failed");
#endif
  }
#elif defined(__sun) && defined(__SVR4)
  memset(testbuf,0,sizeof testbuf);
  r = from_device(testbuf,sizeof testbuf,"/devices/pseudo/random@0:urandom",&fd,1);
  if ( r == 0 ){
    to_use = UWT_RANDOM_URANDOM_DEVICE;
  }
  else {
    DEBUG_PF("/devices/pseudo/random@0:urandom failed");
    memset(testbuf,0,sizeof testbuf);
    r = from_device(testbuf,sizeof testbuf,"/dev/urandom",&fd,0);
    if ( r == 0 ){
      to_use = UWT_RANDOM_URANDOM_DEVICE;
    }
  }
#else
  r = from_device(testbuf,sizeof testbuf,"/dev/urandom",&fd,0);
  if ( r == 0 ){
    to_use = UWT_RANDOM_URANDOM_DEVICE;
  }
  else {
    DEBUG_PF("/devices/urandom failed");
  }
#endif
  switch ( to_use ){
  case UWT_RANDOM_URANDOM_DEVICE:
    w->p1 = (void*)1;
    w->p2 = (void*)(intptr_t)fd;
    break;
  case UWT_RANDOM_BACKUP_SYSCALL:
    w->p1 = (void*)2;
    w->p2 = NULL;
    break;
  default: assert(0); /* fall */
  case UWT_RANDOM_ERROR:
    w->p1 = NULL;
    w->p2 = NULL;
  }
}

static void
uwt_random_cleanup(uv_req_t * req)
{
  struct worker_params * w = req->data;
  if ( w->p1 == (void*)1 ){
    int fd = (int)(intptr_t)w->p2;
    close(fd);
  }
  w->p1 = NULL;
  w->p2 = NULL;
}

/* return:
   | Error
   | Custom of info
   | Fd of Unix.file_descr
   info:
    0: use dedicated_syscall (linux, various bsd systems)
    1: use backup_syscall (linux only)
    nativeint: windows
 */
static value
uwt_random_camlval(uv_req_t * req)
{
  CAMLparam0();
  CAMLlocal2(wrap,cont);
  struct worker_params * w = req->data;
  if ( w->p1 == (void*) 1 ){
    wrap = caml_alloc_small(1,1);
    Field(wrap,0) = Val_long((intnat)w->p2);
  }
  else if ( w->p1 == (void*) 2 ){
    wrap = caml_alloc_small(1,0);
    Field(wrap,0) = Val_long(1);
  }
  else {
    assert ( w->p1 == NULL );
    wrap = Val_long(0);
  }
  w->p1 = NULL;
  w->p2 = NULL;
  CAMLreturn(wrap);
}

CAMLprim value
uwt_random_uwt_init(value o_user, value o_uwt)
{
  CAMLparam2(o_user,o_uwt);
  value ret;
  (void)o_user;
  ret = uwt_add_worker(o_uwt,
                       uwt_random_cleanup,
                       uwt_random_worker,
                       uwt_random_camlval,
                       NULL,
                       NULL);
  CAMLreturn(ret);
}

#else
CAMLprim value
uwt_random_uwt_init(value o_user, value o_uwt)
{
  (void) o_user;
  (void) o_uwt;
  return VAL_UWT_INT_RESULT_UNKNOWN;
}
#endif /* #ifndef _WIN32 */

CAMLextern value uwt_random_uwt_linux_init(value o_user, value o_uwt);

#if defined(_WIN32) || !defined(HAVE_GETRANDOM_INTERFACE) || !defined(HAVE_GETRANDOM_SYSCALL)
CAMLprim value
uwt_random_uwt_linux_init(value o_user, value o_uwt)
{
  return VAL_UWT_INT_RESULT_ENOSYS;
}
#else

static void
uwt_linux_random_worker(uv_work_t * req)
{
  struct worker_params * w = req->data;
  unsigned char testbuf[2];
  intnat x = linux_getrandom(testbuf,2,0);
  w->p1 = (void*)x;
  w->p2 = (void*)1;
  DEBUG_PF("linux would block worker:%d",(int)x);
}

static value
uwt_linux_random_camlval(uv_req_t * req)
{
  struct worker_params * w = req->data;
  int p1 = (intptr_t)w->p1;
  int p2 = (intptr_t)w->p2;
  value ret;
  if ( p2 == 1 && p1 == 0 ){
    ret = caml_alloc_small(1,0);
    Field(ret,0) = Val_long(0);
  }
  else {
    ret = Val_long(0);
  }
  w->p1 = NULL;
  w->p2 = NULL;
  return ret;
}

CAMLprim value
uwt_random_uwt_linux_init(value o_user, value o_uwt)
{
  CAMLparam2(o_user,o_uwt);
  value ret;
  (void)o_user;
  ret = uwt_add_worker(o_uwt,
                       NULL,
                       uwt_linux_random_worker,
                       uwt_linux_random_camlval,
                       NULL,
                       NULL);
  CAMLreturn(ret);
}
#endif

CAMLextern value
uwt_random_read(value ofd, value obuf, value ofs, value olen);

CAMLprim value
uwt_random_read(value ofd, value obytes, value ofs, value olen)
{
#ifndef _WIN32
  int fd = Long_val(ofd);
  char * buf;
  ssize_t count = Long_val(olen);
  ssize_t ret;
  if ( Tag_val(obytes) == 0 ){
    buf = String_val(Field(obytes,0));
  }
  else {
    buf = (char*)Ba_buf_val(Field(obytes,0));
  }
  buf+= Long_val(ofs);
  do {
    ret = read(fd,buf,count);
  } while ( ret == -1 && errno == EINTR );
  return Val_long(ret);
#else
  (void) ofd;
  (void) obytes;
  (void) ofs;
  (void) olen;
  return Val_long(-1);
#endif
}
