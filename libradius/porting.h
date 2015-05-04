#ifndef __PORTING_H__
#define __PORTING_H__

#if !defined(__FreeBSD__) && !defined(__linux__)
typedef unsigned int u_int32_t;
#endif

#ifdef WITH_SSL

#include <openssl/hmac.h>
#include <openssl/md5.h>
#define MD5Init      MD5_Init
#define MD5Update    MD5_Update
#define MD5Final     MD5_Final

#else

#include "md5.h"
#define MD5_DIGEST_LENGTH 16
#define MD5Final    xrad_MD5Final
#define MD5Init     xrad_MD5Init
#define MD5Pad      xrad_MD5Pad
#define MD5Update   xrad_MD5Update

#endif

#endif /* __PORTING_H__ */

