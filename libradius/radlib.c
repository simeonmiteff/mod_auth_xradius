/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MPPE_KEY_LEN 16

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "porting.h"
#include "radlib_private.h"

#include "apr_general.h"

static void	 clear_password(struct xrad_handle *);
static void	 generr(struct xrad_handle *, const char *, ...);
static void	 insert_scrambled_password(struct xrad_handle *, int);
static void	 insert_request_authenticator(struct xrad_handle *, int);
static void	 insert_message_authenticator(struct xrad_handle *, int);
static int	 is_valid_response(struct xrad_handle *, int,
		    const struct sockaddr_in *);
static int	 put_password_attr(struct xrad_handle *, int,
		    const void *, size_t);
static int	 put_raw_attr(struct xrad_handle *, int,
		    const void *, size_t);
static int	 split(char *, char *[], int, char *, size_t);

#if !defined(__FreeBSD__) && !defined(__linux__)
static char *strsep(char **stringp, const char *delim)
{
    char *s;
    const char *spanp;
    int c, sc;
    char *tok;

    if ((s = *stringp) == NULL)
        return (NULL);
    for (tok = s;;) {
        c = *s++;
        spanp = delim;
        do {
            if ((sc = *spanp++) == c) {
                if (c == 0)
                    s = NULL;
                else
                    s[-1] = 0;
                *stringp = s;
                return (tok);
            }
        } while (sc != 0);
    }
    /* NOTREACHED */
}
#endif

static void
clear_password(struct xrad_handle *h)
{
	if (h->pass_len != 0) {
		memset(h->pass, 0, h->pass_len);
		h->pass_len = 0;
	}
	h->pass_pos = 0;
}

static void
generr(struct xrad_handle *h, const char *format, ...)
{
	va_list		 ap;

	va_start(ap, format);
	vsnprintf(h->errmsg, ERRSIZE, format, ap);
	va_end(ap);
}

static void
insert_scrambled_password(struct xrad_handle *h, int srv)
{
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	const struct xrad_server *srvp;
	int padded_len;
	int pos;

	srvp = &h->servers[srv];
	padded_len = h->pass_len == 0 ? 16 : (h->pass_len+15) & ~0xf;

	memcpy(md5, &h->request[POS_AUTH], LEN_AUTH);
	for (pos = 0;  pos < padded_len;  pos += 16) {
		int i;

		/* Calculate the new scrambler */
		MD5Init(&ctx);
		MD5Update(&ctx, srvp->secret, strlen(srvp->secret));
		MD5Update(&ctx, md5, 16);
		MD5Final(md5, &ctx);

		/*
		 * Mix in the current chunk of the password, and copy
		 * the result into the right place in the request.  Also
		 * modify the scrambler in place, since we will use this
		 * in calculating the scrambler for next time.
		 */
		for (i = 0;  i < 16;  i++)
			h->request[h->pass_pos + pos + i] =
			    md5[i] ^= h->pass[pos + i];
	}
}

static void
insert_request_authenticator(struct xrad_handle *h, int srv)
{
	MD5_CTX ctx;
	const struct xrad_server *srvp;

	srvp = &h->servers[srv];

	/* Create the request authenticator */
	MD5Init(&ctx);
	MD5Update(&ctx, &h->request[POS_CODE], POS_AUTH - POS_CODE);
        apr_generate_random_bytes(&h->request[POS_AUTH], LEN_AUTH);
	MD5Update(&ctx, &h->request[POS_AUTH], LEN_AUTH);
	MD5Update(&ctx, &h->request[POS_ATTRS], h->req_len - POS_ATTRS);
	MD5Update(&ctx, srvp->secret, strlen(srvp->secret));
	MD5Final(&h->request[POS_AUTH], &ctx);
}

static void
insert_message_authenticator(struct xrad_handle *h, int srv)
{
#ifdef WITH_SSL
	u_char md[EVP_MAX_MD_SIZE];
	u_int md_len;
	const struct xrad_server *srvp;
	HMAC_CTX ctx;
	srvp = &h->servers[srv];

	if (h->authentic_pos != 0) {
		HMAC_CTX_init(&ctx);
		HMAC_Init(&ctx, srvp->secret, strlen(srvp->secret), EVP_md5());
		HMAC_Update(&ctx, &h->request[POS_CODE], POS_AUTH - POS_CODE);
		HMAC_Update(&ctx, &h->request[POS_AUTH], LEN_AUTH);
		HMAC_Update(&ctx, &h->request[POS_ATTRS],
		    h->req_len - POS_ATTRS);
		HMAC_Final(&ctx, md, &md_len);
		HMAC_CTX_cleanup(&ctx);
		HMAC_cleanup(&ctx);
		memcpy(&h->request[h->authentic_pos + 2], md, md_len);
	}
#endif
}

/*
 * Return true if the current response is valid for a request to the
 * specified server.
 */
static int
is_valid_response(struct xrad_handle *h, int srv,
    const struct sockaddr_in *from)
{
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	const struct xrad_server *srvp;
	int len;
#ifdef WITH_SSL
	HMAC_CTX hctx;
	u_char resp[MSGSIZE], md[EVP_MAX_MD_SIZE];
	int pos, md_len;
#endif

	srvp = &h->servers[srv];

	/* Check the source address */
	if (from->sin_family != srvp->addr.sin_family ||
	    from->sin_addr.s_addr != srvp->addr.sin_addr.s_addr ||
	    from->sin_port != srvp->addr.sin_port)
		return 0;

	/* Check the message length */
	if (h->resp_len < POS_ATTRS)
		return 0;
	len = h->response[POS_LENGTH] << 8 | h->response[POS_LENGTH+1];
	if (len > h->resp_len)
		return 0;

	/* Check the response authenticator */
	MD5Init(&ctx);
	MD5Update(&ctx, &h->response[POS_CODE], POS_AUTH - POS_CODE);
	MD5Update(&ctx, &h->request[POS_AUTH], LEN_AUTH);
	MD5Update(&ctx, &h->response[POS_ATTRS], len - POS_ATTRS);
	MD5Update(&ctx, srvp->secret, strlen(srvp->secret));
	MD5Final(md5, &ctx);
	if (memcmp(&h->response[POS_AUTH], md5, sizeof md5) != 0)
		return 0;

#ifdef WITH_SSL
	/*
	 * For non accounting responses check the message authenticator,
	 * if any.
	 */
	if (h->response[POS_CODE] != RAD_ACCOUNTING_RESPONSE) {

		memcpy(resp, h->response, MSGSIZE);
		pos = POS_ATTRS;

		/* Search and verify the Message-Authenticator */
		while (pos < len - 2) {

			if (h->response[pos] == RAD_MESSAGE_AUTHENTIC) {
				/* zero fill the Message-Authenticator */
				memset(&resp[pos + 2], 0, MD5_DIGEST_LENGTH);

				HMAC_CTX_init(&hctx);
				HMAC_Init(&hctx, srvp->secret,
				    strlen(srvp->secret), EVP_md5());
				HMAC_Update(&hctx, &h->response[POS_CODE],
				    POS_AUTH - POS_CODE);
				HMAC_Update(&hctx, &h->request[POS_AUTH],
				    LEN_AUTH);
				HMAC_Update(&hctx, &resp[POS_ATTRS],
				    h->resp_len - POS_ATTRS);
				HMAC_Final(&hctx, md, &md_len);
				HMAC_CTX_cleanup(&hctx);
				HMAC_cleanup(&hctx);
				if (memcmp(md, &h->response[pos + 2],
				    MD5_DIGEST_LENGTH) != 0)
					return 0;
				break;
			}
			pos += h->response[pos + 1];
		}
	}
#endif
	return 1;
}

static int
put_password_attr(struct xrad_handle *h, int type, const void *value, size_t len)
{
	int padded_len;
	int pad_len;

	if (h->pass_pos != 0) {
		generr(h, "Multiple User-Password attributes specified");
		return -1;
	}
	if (len > PASSSIZE)
		len = PASSSIZE;
	padded_len = len == 0 ? 16 : (len+15) & ~0xf;
	pad_len = padded_len - len;

	/*
	 * Put in a place-holder attribute containing all zeros, and
	 * remember where it is so we can fill it in later.
	 */
	clear_password(h);
	put_raw_attr(h, type, h->pass, padded_len);
	h->pass_pos = h->req_len - padded_len;

	/* Save the cleartext password, padded as necessary */
	memcpy(h->pass, value, len);
	h->pass_len = len;
	memset(h->pass + len, 0, pad_len);
	return 0;
}

static int
put_raw_attr(struct xrad_handle *h, int type, const void *value, size_t len)
{
	if (len > 253) {
		generr(h, "Attribute too long");
		return -1;
	}
	if (h->req_len + 2 + len > MSGSIZE) {
		generr(h, "Maximum message length exceeded");
		return -1;
	}
	h->request[h->req_len++] = type;
	h->request[h->req_len++] = len + 2;
	memcpy(&h->request[h->req_len], value, len);
	h->req_len += len;
	return 0;
}

int
xrad_add_server(struct xrad_handle *h, const char *host, int port,
    const char *secret, int timeout, int tries)
{
	struct xrad_server *srvp;

	if (h->num_servers >= MAXSERVERS) {
		generr(h, "Too many RADIUS servers specified");
		return -1;
	}
	srvp = &h->servers[h->num_servers];

	memset(&srvp->addr, 0, sizeof srvp->addr);
#if defined(__FreeBSD__)
	srvp->addr.sin_len = sizeof srvp->addr;
#endif
	srvp->addr.sin_family = AF_INET;
	if (!inet_aton(host, &srvp->addr.sin_addr)) {
		struct hostent *hent;

		if ((hent = gethostbyname(host)) == NULL) {
			generr(h, "%s: host not found", host);
			return -1;
		}
		memcpy(&srvp->addr.sin_addr, hent->h_addr,
		    sizeof srvp->addr.sin_addr);
	}
	if (port != 0)
		srvp->addr.sin_port = htons((u_short)port);
	else {
		struct servent *sent;

		if (h->type == RADIUS_AUTH)
			srvp->addr.sin_port =
			    (sent = getservbyname("radius", "udp")) != NULL ?
				sent->s_port : htons(RADIUS_PORT);
		else
			srvp->addr.sin_port =
			    (sent = getservbyname("radacct", "udp")) != NULL ?
				sent->s_port : htons(RADACCT_PORT);
	}
	if ((srvp->secret = strdup(secret)) == NULL) {
		generr(h, "Out of memory");
		return -1;
	}
	srvp->timeout = timeout;
	srvp->max_tries = tries;
	srvp->num_tries = 0;
	h->num_servers++;
	return 0;
}

void
xrad_close(struct xrad_handle *h)
{
	int srv;

	if (h->fd != -1)
		close(h->fd);
	for (srv = 0;  srv < h->num_servers;  srv++) {
		memset(h->servers[srv].secret, 0,
		    strlen(h->servers[srv].secret));
		free(h->servers[srv].secret);
	}
	clear_password(h);
	free(h);
}

int
xrad_config(struct xrad_handle *h, const char *path)
{
	FILE *fp;
	char buf[MAXCONFLINE];
	int linenum;
	int retval;

	if (path == NULL)
		path = PATH_RADIUS_CONF;
	if ((fp = fopen(path, "r")) == NULL) {
		generr(h, "Cannot open \"%s\": %s", path, strerror(errno));
		return -1;
	}
	retval = 0;
	linenum = 0;
	while (fgets(buf, sizeof buf, fp) != NULL) {
		int len;
		char *fields[5];
		int nfields;
		char msg[ERRSIZE];
		char *type;
		char *host, *res;
		char *port_str;
		char *secret;
		char *timeout_str;
		char *maxtries_str;
		char *end;
		char *wanttype;
		unsigned long timeout;
		unsigned long maxtries;
		int port;
		int i;

		linenum++;
		len = strlen(buf);
		/* We know len > 0, else fgets would have returned NULL. */
		if (buf[len - 1] != '\n') {
			if (len == sizeof buf - 1)
				generr(h, "%s:%d: line too long", path,
				    linenum);
			else
				generr(h, "%s:%d: missing newline", path,
				    linenum);
			retval = -1;
			break;
		}
		buf[len - 1] = '\0';

		/* Extract the fields from the line. */
		nfields = split(buf, fields, 5, msg, sizeof msg);
		if (nfields == -1) {
			generr(h, "%s:%d: %s", path, linenum, msg);
			retval = -1;
			break;
		}
		if (nfields == 0)
			continue;
		/*
		 * The first field should contain "auth" or "acct" for
		 * authentication or accounting, respectively.  But older
		 * versions of the file didn't have that field.  Default
		 * it to "auth" for backward compatibility.
		 */
		if (strcmp(fields[0], "auth") != 0 &&
		    strcmp(fields[0], "acct") != 0) {
			if (nfields >= 5) {
				generr(h, "%s:%d: invalid service type", path,
				    linenum);
				retval = -1;
				break;
			}
			nfields++;
			for (i = nfields;  --i > 0;  )
				fields[i] = fields[i - 1];
			fields[0] = "auth";
		}
		if (nfields < 3) {
			generr(h, "%s:%d: missing shared secret", path,
			    linenum);
			retval = -1;
			break;
		}
		type = fields[0];
		host = fields[1];
		secret = fields[2];
		timeout_str = fields[3];
		maxtries_str = fields[4];

		/* Ignore the line if it is for the wrong service type. */
		wanttype = h->type == RADIUS_AUTH ? "auth" : "acct";
		if (strcmp(type, wanttype) != 0)
			continue;

		/* Parse and validate the fields. */
		res = host;
		host = strsep(&res, ":");
		port_str = strsep(&res, ":");
		if (port_str != NULL) {
			port = strtoul(port_str, &end, 10);
			if (*end != '\0') {
				generr(h, "%s:%d: invalid port", path,
				    linenum);
				retval = -1;
				break;
			}
		} else
			port = 0;
		if (timeout_str != NULL) {
			timeout = strtoul(timeout_str, &end, 10);
			if (*end != '\0') {
				generr(h, "%s:%d: invalid timeout", path,
				    linenum);
				retval = -1;
				break;
			}
		} else
			timeout = TIMEOUT;
		if (maxtries_str != NULL) {
			maxtries = strtoul(maxtries_str, &end, 10);
			if (*end != '\0') {
				generr(h, "%s:%d: invalid maxtries", path,
				    linenum);
				retval = -1;
				break;
			}
		} else
			maxtries = MAXTRIES;

		if (xrad_add_server(h, host, port, secret, timeout, maxtries) ==
		    -1) {
			strcpy(msg, h->errmsg);
			generr(h, "%s:%d: %s", path, linenum, msg);
			retval = -1;
			break;
		}
	}
	/* Clear out the buffer to wipe a possible copy of a shared secret */
	memset(buf, 0, sizeof buf);
	fclose(fp);
	return retval;
}

/*
 * xrad_init_send_request() must have previously been called.
 * Returns:
 *   0     The application should select on *fd with a timeout of tv before
 *         calling xrad_continue_send_request again.
 *   < 0   Failure
 *   > 0   Success
 */
int
xrad_continue_send_request(struct xrad_handle *h, int selected, int *fd,
                          struct timeval *tv)
{
	int n;

	if (selected) {
		struct sockaddr_in from;
		int fromlen;

		fromlen = sizeof from;
		h->resp_len = recvfrom(h->fd, h->response,
		    MSGSIZE, MSG_WAITALL, (struct sockaddr *)&from, &fromlen);
		if (h->resp_len == -1) {
			generr(h, "recvfrom: %s", strerror(errno));
			return -1;
		}
		if (is_valid_response(h, h->srv, &from)) {
			h->resp_len = h->response[POS_LENGTH] << 8 |
			    h->response[POS_LENGTH+1];
			h->resp_pos = POS_ATTRS;
			return h->response[POS_CODE];
		}
	}

	if (h->try == h->total_tries) {
		generr(h, "No valid RADIUS responses received");
		return -1;
	}

	/*
         * Scan round-robin to the next server that has some
         * tries left.  There is guaranteed to be one, or we
         * would have exited this loop by now.
	 */
	while (h->servers[h->srv].num_tries >= h->servers[h->srv].max_tries)
		if (++h->srv >= h->num_servers)
			h->srv = 0;

	insert_request_authenticator(h, h->srv);

	if (h->request[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		/* Insert the request authenticator into the request */
	}
	else {
		/* Insert the scrambled password into the request */
		if (h->pass_pos != 0) {
			insert_scrambled_password(h, h->srv);
		}
	}

	insert_message_authenticator(h, h->srv);

	/* Send the request */
	n = sendto(h->fd, h->request, h->req_len, 0,
	    (const struct sockaddr *)&h->servers[h->srv].addr,
	    sizeof h->servers[h->srv].addr);
	if (n != h->req_len) {
		if (n == -1)
			generr(h, "sendto: %s", strerror(errno));
		else
			generr(h, "sendto: short write");
		return -1;
	}

	h->try++;
	h->servers[h->srv].num_tries++;
	tv->tv_sec = h->servers[h->srv].timeout;
	tv->tv_usec = 0;
	*fd = h->fd;

	return 0;
}

int
xrad_create_request(struct xrad_handle *h, int code)
{
	int i;

	h->request[POS_CODE] = code;
	h->request[POS_IDENT] = ++h->ident;
	/* Create a random authenticator */
	for (i = 0;  i < LEN_AUTH;  i += 2) {
		long r;
		r = random();
		h->request[POS_AUTH+i] = (u_char)r;
		h->request[POS_AUTH+i+1] = (u_char)(r >> 8);
	}
	h->req_len = POS_ATTRS;
	clear_password(h);
	h->request_created = 1;
	return 0;
}

struct in_addr
xrad_cvt_addr(const void *data)
{
	struct in_addr value;

	memcpy(&value.s_addr, data, sizeof value.s_addr);
	return value;
}

u_int32_t
xrad_cvt_int(const void *data)
{
	u_int32_t value;

	memcpy(&value, data, sizeof value);
	return ntohl(value);
}

char *
xrad_cvt_string(const void *data, size_t len)
{
	char *s;

	s = malloc(len + 1);
	if (s != NULL) {
		memcpy(s, data, len);
		s[len] = '\0';
	}
	return s;
}

/*
 * Returns the attribute type.  If none are left, returns 0.  On failure,
 * returns -1.
 */
int
xrad_get_attr(struct xrad_handle *h, const void **value, size_t *len)
{
	int type;

	if (h->resp_pos >= h->resp_len)
		return 0;
	if (h->resp_pos + 2 > h->resp_len) {
		generr(h, "Malformed attribute in response");
		return -1;
	}
	type = h->response[h->resp_pos++];
	*len = h->response[h->resp_pos++] - 2;
	if (h->resp_pos + (int)*len > h->resp_len) {
		generr(h, "Malformed attribute in response");
		return -1;
	}
	*value = &h->response[h->resp_pos];
	h->resp_pos += *len;
	return type;
}

/*
 * Returns -1 on error, 0 to indicate no event and >0 for success
 */
int
xrad_init_send_request(struct xrad_handle *h, int *fd, struct timeval *tv)
{
	int srv;

	/* Make sure we have a socket to use */
	if (h->fd == -1) {
		struct sockaddr_in sin;

		if ((h->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			generr(h, "Cannot create socket: %s", strerror(errno));
			return -1;
		}
		memset(&sin, 0, sizeof sin);
#if defined(__FreeBSD__)
		sin.sin_len = sizeof sin;
#endif
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(0);
		if (bind(h->fd, (const struct sockaddr *)&sin,
		    sizeof sin) == -1) {
			generr(h, "bind: %s", strerror(errno));
			close(h->fd);
			h->fd = -1;
			return -1;
		}
	}

	if (h->request[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		/* Make sure no password given */
		if (h->pass_pos || h->chap_pass) {
			generr(h, "User or Chap Password"
			    " in accounting request");
			return -1;
		}
	} else {
		if (h->eap_msg == 0) {
			/* Make sure the user gave us a password */
			if (h->pass_pos == 0 && !h->chap_pass) {
				generr(h, "No User or Chap Password"
				    " attributes given");
				return -1;
			}
			if (h->pass_pos != 0 && h->chap_pass) {
				generr(h, "Both User and Chap Password"
				    " attributes given");
				return -1;
			}
		}
	}

	/* Fill in the length field in the message */
	h->request[POS_LENGTH] = h->req_len >> 8;
	h->request[POS_LENGTH+1] = h->req_len;

	/*
	 * Count the total number of tries we will make, and zero the
	 * counter for each server.
	 */
	h->total_tries = 0;
	for (srv = 0;  srv < h->num_servers;  srv++) {
		h->total_tries += h->servers[srv].max_tries;
		h->servers[srv].num_tries = 0;
	}
	if (h->total_tries == 0) {
		generr(h, "No RADIUS servers specified");
		return -1;
	}

	h->try = h->srv = 0;

	return xrad_continue_send_request(h, 0, fd, tv);
}

/*
 * Create and initialize a xrad_handle structure, and return it to the
 * caller.  Can fail only if the necessary memory cannot be allocated.
 * In that case, it returns NULL.
 */
struct xrad_handle *
xrad_auth_open(void)
{
	struct xrad_handle *h;

	h = (struct xrad_handle *)malloc(sizeof(struct xrad_handle));
	if (h != NULL) {
#if defined(__FreeBSD__)
		srandomdev();
#else
		srand(243);
#endif
		h->fd = -1;
		h->num_servers = 0;
		h->ident = random();
		h->errmsg[0] = '\0';
		memset(h->pass, 0, sizeof h->pass);
		h->pass_len = 0;
		h->pass_pos = 0;
		h->chap_pass = 0;
		h->authentic_pos = 0;
		h->type = RADIUS_AUTH;
		h->request_created = 0;
		h->eap_msg = 0;
	}
	return h;
}

struct xrad_handle *
xrad_acct_open(void)
{
	struct xrad_handle *h;

	h = xrad_open();
	if (h != NULL)
	        h->type = RADIUS_ACCT;
	return h;
}

struct xrad_handle *
xrad_open(void)
{
    return xrad_auth_open();
}

int
xrad_put_addr(struct xrad_handle *h, int type, struct in_addr addr)
{
	return xrad_put_attr(h, type, &addr.s_addr, sizeof addr.s_addr);
}

int
xrad_put_attr(struct xrad_handle *h, int type, const void *value, size_t len)
{
	int result;

	if (!h->request_created) {
		generr(h, "Please call xrad_create_request()"
		    " before putting attributes");
		return -1;
	}

	if (h->request[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		if (type == RAD_EAP_MESSAGE) {
			generr(h, "EAP-Message attribute is not valid"
			    " in accounting requests");
			return -1;
		}
	}

	/*
	 * When proxying EAP Messages, the Message Authenticator
	 * MUST be present; see RFC 3579.
	 */
	if (type == RAD_EAP_MESSAGE) {
		if (xrad_put_message_authentic(h) == -1)
			return -1;
	}

	if (type == RAD_USER_PASSWORD) {
		result = put_password_attr(h, type, value, len);
	} else if (type == RAD_MESSAGE_AUTHENTIC) {
		result = xrad_put_message_authentic(h);
	} else {
		result = put_raw_attr(h, type, value, len);
		if (result == 0) {
			if (type == RAD_CHAP_PASSWORD)
				h->chap_pass = 1;
			else if (type == RAD_EAP_MESSAGE)
				h->eap_msg = 1;
		}
	}

	return result;
}

int
xrad_put_int(struct xrad_handle *h, int type, u_int32_t value)
{
	u_int32_t nvalue;

	nvalue = htonl(value);
	return xrad_put_attr(h, type, &nvalue, sizeof nvalue);
}

int
xrad_put_string(struct xrad_handle *h, int type, const char *str)
{
	return xrad_put_attr(h, type, str, strlen(str));
}

int
xrad_put_message_authentic(struct xrad_handle *h)
{
#ifdef WITH_SSL
	u_char md_zero[MD5_DIGEST_LENGTH];

	if (h->request[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		generr(h, "Message-Authenticator is not valid"
		    " in accounting requests");
		return -1;
	}

	if (h->authentic_pos == 0) {
		h->authentic_pos = h->req_len;
		memset(md_zero, 0, sizeof(md_zero));
		return (put_raw_attr(h, RAD_MESSAGE_AUTHENTIC, md_zero,
		    sizeof(md_zero)));
	}
	return 0;
#else
	generr(h, "Message Authenticator not supported,"
	    " please recompile libradius with SSL support");
	return -1;
#endif
}

/*
 * Returns the response type code on success, or -1 on failure.
 */
int
xrad_send_request(struct xrad_handle *h)
{
	struct timeval timelimit;
	struct timeval tv;
	int fd;
	int n;

	n = xrad_init_send_request(h, &fd, &tv);

	if (n != 0)
		return n;

	gettimeofday(&timelimit, NULL);
	timeradd(&tv, &timelimit, &timelimit);

	for ( ; ; ) {
		fd_set readfds;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		n = select(fd + 1, &readfds, NULL, NULL, &tv);

		if (n == -1) {
			generr(h, "select: %s", strerror(errno));
			return -1;
		}

		if (!FD_ISSET(fd, &readfds)) {
			/* Compute a new timeout */
			gettimeofday(&tv, NULL);
			timersub(&timelimit, &tv, &tv);
			if (tv.tv_sec > 0 || (tv.tv_sec == 0 && tv.tv_usec > 0))
				/* Continue the select */
				continue;
		}

		n = xrad_continue_send_request(h, n, &fd, &tv);

		if (n != 0)
			return n;

		gettimeofday(&timelimit, NULL);
		timeradd(&tv, &timelimit, &timelimit);
	}
}

const char *
xrad_strerror(struct xrad_handle *h)
{
	return h->errmsg;
}

/*
 * Destructively split a string into fields separated by white space.
 * `#' at the beginning of a field begins a comment that extends to the
 * end of the string.  Fields may be quoted with `"'.  Inside quoted
 * strings, the backslash escapes `\"' and `\\' are honored.
 *
 * Pointers to up to the first maxfields fields are stored in the fields
 * array.  Missing fields get NULL pointers.
 *
 * The return value is the actual number of fields parsed, and is always
 * <= maxfields.
 *
 * On a syntax error, places a message in the msg string, and returns -1.
 */
static int
split(char *str, char *fields[], int maxfields, char *msg, size_t msglen)
{
	char *p;
	int i;
	static const char ws[] = " \t";

	for (i = 0;  i < maxfields;  i++)
		fields[i] = NULL;
	p = str;
	i = 0;
	while (*p != '\0') {
		p += strspn(p, ws);
		if (*p == '#' || *p == '\0')
			break;
		if (i >= maxfields) {
			snprintf(msg, msglen, "line has too many fields");
			return -1;
		}
		if (*p == '"') {
			char *dst;

			dst = ++p;
			fields[i] = dst;
			while (*p != '"') {
				if (*p == '\\') {
					p++;
					if (*p != '"' && *p != '\\' &&
					    *p != '\0') {
						snprintf(msg, msglen,
						    "invalid `\\' escape");
						return -1;
					}
				}
				if (*p == '\0') {
					snprintf(msg, msglen,
					    "unterminated quoted string");
					return -1;
				}
				*dst++ = *p++;
			}
			*dst = '\0';
			p++;
			if (*fields[i] == '\0') {
				snprintf(msg, msglen,
				    "empty quoted string not permitted");
				return -1;
			}
			if (*p != '\0' && strspn(p, ws) == 0) {
				snprintf(msg, msglen, "quoted string not"
				    " followed by white space");
				return -1;
			}
		} else {
			fields[i] = p;
			p += strcspn(p, ws);
			if (*p != '\0')
				*p++ = '\0';
		}
		i++;
	}
	return i;
}

int
xrad_get_vendor_attr(u_int32_t *vendor, const void **data, size_t *len)
{
	struct vendor_attribute *attr;

	attr = (struct vendor_attribute *)*data;
	*vendor = ntohl(attr->vendor_value);
	*data = attr->attrib_data;
	*len = attr->attrib_len - 2;

	return (attr->attrib_type);
}

int
xrad_put_vendor_addr(struct xrad_handle *h, int vendor, int type,
    struct in_addr addr)
{
	return (xrad_put_vendor_attr(h, vendor, type, &addr.s_addr,
	    sizeof addr.s_addr));
}

int
xrad_put_vendor_attr(struct xrad_handle *h, int vendor, int type,
    const void *value, size_t len)
{
	struct vendor_attribute *attr;
	int res;

	if (!h->request_created) {
		generr(h, "Please call xrad_create_request()"
		    " before putting attributes");
		return -1;
	}

	if ((attr = malloc(len + 6)) == NULL) {
		generr(h, "malloc failure (%zu bytes)", len + 6);
		return -1;
	}

	attr->vendor_value = htonl(vendor);
	attr->attrib_type = type;
	attr->attrib_len = len + 2;
	memcpy(attr->attrib_data, value, len);

	res = put_raw_attr(h, RAD_VENDOR_SPECIFIC, attr, len + 6);
	free(attr);
	if (res == 0 && vendor == RAD_VENDOR_MICROSOFT
	    && (type == RAD_MICROSOFT_MS_CHAP_RESPONSE
	    || type == RAD_MICROSOFT_MS_CHAP2_RESPONSE)) {
		h->chap_pass = 1;
	}
	return (res);
}

int
xrad_put_vendor_int(struct xrad_handle *h, int vendor, int type, u_int32_t i)
{
	u_int32_t value;

	value = htonl(i);
	return (xrad_put_vendor_attr(h, vendor, type, &value, sizeof value));
}

int
xrad_put_vendor_string(struct xrad_handle *h, int vendor, int type,
    const char *str)
{
	return (xrad_put_vendor_attr(h, vendor, type, str, strlen(str)));
}

ssize_t
xrad_request_authenticator(struct xrad_handle *h, char *buf, size_t len)
{
	if (len < LEN_AUTH)
		return (-1);
	memcpy(buf, h->request + POS_AUTH, LEN_AUTH);
	if (len > LEN_AUTH)
		buf[LEN_AUTH] = '\0';
	return (LEN_AUTH);
}

u_char *
xrad_demangle(struct xrad_handle *h, const void *mangled, size_t mlen)
{
	char R[LEN_AUTH];
	const char *S;
	int i, Ppos;
	MD5_CTX Context;
	u_char b[MD5_DIGEST_LENGTH], *C, *demangled;

	if ((mlen % 16 != 0) || mlen > 128) {
		generr(h, "Cannot interpret mangled data of length %lu",
		    (u_long)mlen);
		return NULL;
	}

	C = (u_char *)mangled;

	/* We need the shared secret as Salt */
	S = xrad_server_secret(h);

	/* We need the request authenticator */
	if (xrad_request_authenticator(h, R, sizeof R) != LEN_AUTH) {
		generr(h, "Cannot obtain the RADIUS request authenticator");
		return NULL;
	}

	demangled = malloc(mlen);
	if (!demangled)
		return NULL;

	MD5Init(&Context);
	MD5Update(&Context, S, strlen(S));
	MD5Update(&Context, R, LEN_AUTH);
	MD5Final(b, &Context);
	Ppos = 0;
	while (mlen) {

		mlen -= 16;
		for (i = 0; i < 16; i++)
			demangled[Ppos++] = C[i] ^ b[i];

		if (mlen) {
			MD5Init(&Context);
			MD5Update(&Context, S, strlen(S));
			MD5Update(&Context, C, 16);
			MD5Final(b, &Context);
		}

		C += 16;
	}

	return demangled;
}

u_char *
xrad_demangle_mppe_key(struct xrad_handle *h, const void *mangled,
    size_t mlen, size_t *len)
{
	char R[LEN_AUTH];    /* variable names as per rfc2548 */
	const char *S;
	u_char b[MD5_DIGEST_LENGTH], *demangled;
	const u_char *A, *C;
	MD5_CTX Context;
	int Slen, i, Clen, Ppos;
	u_char *P;

	if (mlen % 16 != SALT_LEN) {
		generr(h, "Cannot interpret mangled data of length %lu",
		    (u_long)mlen);
		return NULL;
	}

	/* We need the RADIUS Request-Authenticator */
	if (xrad_request_authenticator(h, R, sizeof R) != LEN_AUTH) {
		generr(h, "Cannot obtain the RADIUS request authenticator");
		return NULL;
	}

	A = (const u_char *)mangled;      /* Salt comes first */
	C = (const u_char *)mangled + SALT_LEN;  /* Then the ciphertext */
	Clen = mlen - SALT_LEN;
	S = xrad_server_secret(h);    /* We need the RADIUS secret */
	Slen = strlen(S);
	P = alloca(Clen);        /* We derive our plaintext */

	MD5Init(&Context);
	MD5Update(&Context, S, Slen);
	MD5Update(&Context, R, LEN_AUTH);
	MD5Update(&Context, A, SALT_LEN);
	MD5Final(b, &Context);
	Ppos = 0;

	while (Clen) {
		Clen -= 16;

		for (i = 0; i < 16; i++)
		    P[Ppos++] = C[i] ^ b[i];

		if (Clen) {
			MD5Init(&Context);
			MD5Update(&Context, S, Slen);
			MD5Update(&Context, C, 16);
			MD5Final(b, &Context);
		}

		C += 16;
	}

	/*
	* The resulting plain text consists of a one-byte length, the text and
	* maybe some padding.
	*/
	*len = *P;
	if (*len > mlen - 1) {
		generr(h, "Mangled data seems to be garbage %zu %zu",
		    *len, mlen-1);
		return NULL;
	}

	if (*len > MPPE_KEY_LEN * 2) {
		generr(h, "Key to long (%zu) for me max. %d",
		    *len, MPPE_KEY_LEN * 2);
		return NULL;
	}
	demangled = malloc(*len);
	if (!demangled)
		return NULL;

	memcpy(demangled, P + 1, *len);
	return demangled;
}

const char *
xrad_server_secret(struct xrad_handle *h)
{
	return (h->servers[h->srv].secret);
}
