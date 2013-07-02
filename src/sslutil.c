/*
Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>
        http://www.distrotech.co.za

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "include/dtsapp.h"

enum SSLFLAGS {
	SSL_TLSV1	= 1 << 0,
	SSL_SSLV2	= 1 << 1,
	SSL_SSLV3	= 1 << 2,
	SSL_DTLSV1	= 1 << 3,
	SSL_CLIENT	= 1 << 4,
	SSL_SERVER	= 1 << 5,
	SSL_DTLSCON	= 1 << 6
};

struct ssldata {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	int flags;
	const SSL_METHOD *meth;
	struct ssldata *parent;
};

#define COOKIE_SECRET_LENGTH 32
static unsigned char *cookie_secret = NULL;

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
	union sockstruct peer;

	if (!ssl || !cookie_secret || (*cookie_len < COOKIE_SECRET_LENGTH)) {
		return (0);
	}

	memset(&peer, 0, sizeof(peer));
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	sha256hmac(cookie, &peer, sizeof(peer), cookie_secret, COOKIE_SECRET_LENGTH);
	*cookie_len = COOKIE_SECRET_LENGTH;

	return (1);
}

static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
	union sockstruct peer;
	unsigned char hmac[COOKIE_SECRET_LENGTH];

	if (!ssl || !cookie_secret || (cookie_len != COOKIE_SECRET_LENGTH)) {
		return (0);
	}

	memset(&peer, 0, sizeof(peer));
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	sha256hmac(hmac, &peer, sizeof(peer), cookie_secret, COOKIE_SECRET_LENGTH);

	if (!sha256cmp(hmac, cookie)) {
		return (1);
	}

	return (0);
}

extern void ssl_shutdown(void *data) {
	struct ssldata *ssl = data;
	int err, ret;

	if (!ssl) {
		return;
	}

	objlock(ssl);
	if (ssl->ssl && ((ret = SSL_shutdown(ssl->ssl)) < 1)) {
		objunlock(ssl);
		if (ret == 0) {
			objlock(ssl);
			ret = SSL_shutdown(ssl->ssl);
		} else {
			objlock(ssl);
		}
		err = SSL_get_error(ssl->ssl, ret);
		switch(err) {
			case SSL_ERROR_WANT_READ:
				printf("SSL_shutdown wants read\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				printf("SSL_shutdown wants write\n");
				break;
			case SSL_ERROR_SSL:
				/*ignore im going away now*/
			case SSL_ERROR_SYSCALL:
				/* ignore this as documented*/
			case SSL_ERROR_NONE:
				/* nothing to see here moving on*/
				break;
			default
					:
				printf("SSL Shutdown unknown error %i\n", err);
				break;
		}
	}
	if (ssl->ssl) {
		SSL_free(ssl->ssl);
		ssl->ssl = NULL;
	}
	objunlock(ssl);
}

static void free_ssldata(void *data) {
	struct ssldata *ssl = data;

	if (ssl->parent) {
		objunref(ssl->parent);
	}

	if (ssl->ctx) {
		SSL_CTX_free(ssl->ctx);
		ssl->ctx = NULL;
	}
}

static int verify_callback (int ok, X509_STORE_CTX *ctx) {
	return (1);
}

static struct ssldata *sslinit(const char *cacert, const char *cert, const char *key, int verify, const SSL_METHOD *meth, int flags) {
	struct ssldata *ssl;
	struct stat finfo;
	int ret = -1;

	if (!(ssl = objalloc(sizeof(*ssl), free_ssldata))) {
		return NULL;
	}

	ssl->flags = flags;
	ssl->meth = meth;
	if (!(ssl->ctx = SSL_CTX_new(meth))) {
		objunref(ssl);
		return NULL;
	}

	if (!stat(cacert, &finfo)) {
		if (S_ISDIR(finfo.st_mode) && (SSL_CTX_load_verify_locations(ssl->ctx, NULL, cacert) == 1)) {
			ret = 0;
		} else
			if (SSL_CTX_load_verify_locations(ssl->ctx, cacert, NULL) == 1) {
				ret = 0;
			}
	}

	if (!ret && (SSL_CTX_use_certificate_file(ssl->ctx, cert, SSL_FILETYPE_PEM) == 1)) {
		ret = 0;
	}
	if (!ret && (SSL_CTX_use_PrivateKey_file(ssl->ctx, key, SSL_FILETYPE_PEM) == 1)) {
		ret = 0;
	}

	if (!ret && (SSL_CTX_check_private_key (ssl->ctx) == 1)) {
		ret= 0;
	}

	/*XXX	Should create a tmp 512 bit rsa key for RSA ciphers also need DH
		http://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html
		SSL_CTX_set_cipher_list*/

	if (!ret) {
		/* XXX CRL verification
				X509_VERIFY_PARAM *param;
				param = X509_VERIFY_PARAM_new();
				X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
				SSL_CTX_set1_param(ctx, param);
				X509_VERIFY_PARAM_free(param);
		*/
		SSL_CTX_set_verify(ssl->ctx, verify, verify_callback);
		SSL_CTX_set_verify_depth(ssl->ctx, 1);
	}

	if (ret) {
		objunref(ssl);
		return NULL;
	}

	return (ssl);
}

extern void *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = TLSv1_method();

	return (sslinit(cacert, cert, key, verify, meth, SSL_TLSV1));
}

#ifndef OPENSSL_NO_SSL2
extern void *sslv2_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv2_method();

	return (sslinit(cacert, cert, key, verify, meth, SSL_SSLV2));
}
#endif

extern void *sslv3_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv3_method();
	struct ssldata *ssl;

	ssl = sslinit(cacert, cert, key, verify, meth, SSL_SSLV3);

	return (ssl);
}

extern void *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = DTLSv1_method();
	struct ssldata *ssl;

	ssl = sslinit(cacert, cert, key, verify, meth, SSL_DTLSV1);
	/* XXX BIO_CTRL_DGRAM_MTU_DISCOVER*/
	SSL_CTX_set_read_ahead(ssl->ctx, 1);

	return (ssl);
}

static void sslsockstart(struct fwsocket *sock, struct ssldata *orig,int accept) {
	struct ssldata *ssl = sock->ssl;

	if (!ssl) {
		return;
	}

	objlock(sock);
	objlock(ssl);
	if (orig) {
		objlock(orig);
		ssl->ssl = SSL_new(orig->ctx);
		objunlock(orig);
	} else {
		ssl->ssl = SSL_new(ssl->ctx);
	}

	if (ssl->ssl) {
		ssl->bio = BIO_new_socket(sock->sock, BIO_NOCLOSE);
		objunlock(sock);
		SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
		if (accept) {
			SSL_accept(ssl->ssl);
			ssl->flags |= SSL_SERVER;
		} else {
			SSL_connect(ssl->ssl);
			ssl->flags |= SSL_CLIENT;
		}
		if (orig) {
			objref(orig);
			ssl->parent = orig;
		}
		objunlock(ssl);
	} else {
		objunlock(ssl);
		objunref(ssl);
		sock->ssl = NULL;
		objunlock(sock);
		return;
	}
}

extern void tlsaccept(struct fwsocket *sock, struct ssldata *orig) {
	if ((sock->ssl = objalloc(sizeof(*sock->ssl), free_ssldata))) {
		sslsockstart(sock, orig, 1);
	}

}

extern int socketread_d(struct fwsocket *sock, void *buf, int num, union sockstruct *addr) {
	struct ssldata *ssl = sock->ssl;
	socklen_t salen = sizeof(*addr);
	int ret, err, syserr;

	if (!ssl || !ssl->ssl) {
		objlock(sock);
		if (addr && (sock->type == SOCK_DGRAM)) {
			ret = recvfrom(sock->sock, buf, num, 0, &addr->sa, &salen);
		} else {
			ret = read(sock->sock, buf, num);
		}
		if (ret == 0) {
			sock->flags |= SOCK_FLAG_CLOSE;
		}
		objunlock(sock);
		return (ret);
	}

	objlock(ssl);
	/* ive been shutdown*/
	if (!ssl->ssl) {
		objunlock(ssl);
		return (-1);
	}
	ret = SSL_read(ssl->ssl, buf, num);
	err = SSL_get_error(ssl->ssl, ret);
	if (ret == 0) {
		sock->flags |= SOCK_FLAG_CLOSE;
	}
	objunlock(ssl);
	switch (err) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			printf("Want X509\n");
			break;
		case SSL_ERROR_WANT_READ:
			printf("Want Read\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			printf("Want write\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SSL:
			objlock(sock);
			objunref(sock->ssl);
			sock->ssl = NULL;
			objunlock(sock);
			break;
		case SSL_ERROR_SYSCALL:
			syserr = ERR_get_error();
			if (syserr || (!syserr && (ret == -1))) {
				printf("R syscall %i %i\n", syserr, ret);
			}
			break;
		default
				:
			printf("other\n");
			break;
	}

	return (ret);
}

extern int socketread(struct fwsocket *sock, void *buf, int num) {
	return (socketread_d(sock, buf, num, NULL));
}

extern int socketwrite_d(struct fwsocket *sock, const void *buf, int num, union sockstruct *addr) {
	struct ssldata *ssl = (sock) ? sock->ssl : NULL;
	int ret, err, syserr;

	if (!sock) {
		return (-1);
	}

	if (!ssl || !ssl->ssl) {
		objlock(sock);
		if (addr && (sock->type == SOCK_DGRAM)) {
			ret = sendto(sock->sock, buf, num, MSG_NOSIGNAL, &addr->sa, sizeof(*addr));
		} else {
			ret = send(sock->sock, buf, num, MSG_NOSIGNAL);
		}
		if (ret == -1) {
			switch(errno) {
				case EBADF:
				case EPIPE:
				case ENOTCONN:
				case ENOTSOCK:
					sock->flags |= SOCK_FLAG_CLOSE;
					break;
			}
		}
		objunlock(sock);
		return (ret);
	}

	objlock(ssl);
	if (SSL_state(ssl->ssl) != SSL_ST_OK) {
		objunlock(ssl);
		return (SSL_ERROR_SSL);
	}
	ret = SSL_write(ssl->ssl, buf, num);
	err = SSL_get_error(ssl->ssl, ret);
	objunlock(ssl);

	if (ret == -1) {
		setflag(sock, SOCK_FLAG_CLOSE);
	}

	switch(err) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_READ:
			printf("Want Read\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			printf("Want write\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			printf("Want X509\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SSL:
			objlock(sock);
			objunref(sock->ssl);
			sock->ssl = NULL;
			objunlock(sock);
			break;
		case SSL_ERROR_SYSCALL:
			syserr = ERR_get_error();
			if (syserr || (!syserr && (ret == -1))) {
				printf("W syscall %i %i\n", syserr, ret);
			}
			break;
		default
				:
			printf("other\n");
			break;
	}

	return (ret);
}

extern int socketwrite(struct fwsocket *sock, const void *buf, int num) {
	return (socketwrite_d(sock, buf, num, NULL));
}

extern void sslstartup(void) {
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	if ((cookie_secret = malloc(COOKIE_SECRET_LENGTH))) {
		genrand(cookie_secret, COOKIE_SECRET_LENGTH);
	}
}

static void dtlssetopts(struct ssldata *ssl, struct ssldata *orig, struct fwsocket *sock) {
	struct timeval timeout;

	objlock(sock);
	objlock(ssl);
	ssl->bio = BIO_new_dgram(sock->sock, BIO_NOCLOSE);
	objunlock(sock);

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

	if (orig) {
		objlock(orig);
		if ((ssl->ssl = SSL_new(orig->ctx))) {
			objunlock(orig);
			objref(orig);
			ssl->parent = orig;
		} else {
			objunlock(orig);
		}
	} else {
		ssl->ssl = SSL_new(ssl->ctx);
	}
	SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
	objunlock(ssl);
}

extern void dtsl_serveropts(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;

	if (!ssl) {
		return;
	}

	dtlssetopts(ssl, NULL, sock);

	objlock(ssl);
	SSL_CTX_set_cookie_generate_cb(ssl->ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ssl->ctx, verify_cookie);
	SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);

	SSL_set_options(ssl->ssl, SSL_OP_COOKIE_EXCHANGE);
	ssl->flags |= SSL_SERVER;
	objunlock(ssl);
}

static void dtlsaccept(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;

	objlock(sock);
	objlock(ssl);
	ssl->flags |= SSL_SERVER;

	BIO_set_fd(ssl->bio, sock->sock, BIO_NOCLOSE);
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &sock->addr);
	objunlock(sock);

	SSL_accept(ssl->ssl);

	if (SSL_get_peer_certificate(ssl->ssl)) {
		printf ("A------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl->ssl)), 1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}
	objunlock(ssl);
}

extern struct fwsocket *dtls_listenssl(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;
	struct ssldata *newssl;
	struct fwsocket *newsock;
	union sockstruct client;
	int on = 1;

	if (!(newssl = objalloc(sizeof(*newssl), free_ssldata))) {
		return NULL;
	}

	newssl->flags |= SSL_DTLSCON;

	dtlssetopts(newssl, ssl, sock);
	memset(&client, 0, sizeof(client));
	if (DTLSv1_listen(newssl->ssl, &client) <= 0) {
		objunref(newssl);
		return NULL;
	}

	objlock(sock);
	if (!(newsock = make_socket(sock->addr.sa.sa_family, sock->type, sock->proto, newssl))) {
		objunlock(sock);
		objunref(newssl);
		return NULL;
	}
	objunlock(sock);
	memcpy(&newsock->addr, &client, sizeof(newsock->addr));

	setsockopt(newsock->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(newsock->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

	objlock(sock);
	bind(newsock->sock, &sock->addr.sa, sizeof(sock->addr));
	objunlock(sock);
	connect(newsock->sock, &newsock->addr.sa, sizeof(newsock->addr));

	dtlsaccept(newsock);

	return (newsock);
}

static void dtlsconnect(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;

	if (!ssl) {
		return;
	}

	dtlssetopts(ssl, NULL, sock);

	objlock(sock);
	objlock(ssl);
	ssl->flags |= SSL_CLIENT;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &sock->addr);
	objunlock(sock);
	SSL_connect(ssl->ssl);

	if (SSL_get_peer_certificate(ssl->ssl)) {
		printf ("C------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl->ssl)), 1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}
	objunlock(ssl);
}


extern void startsslclient(struct fwsocket *sock) {
	if (!sock || !sock->ssl || (sock->ssl->flags & SSL_SERVER)) {
		return;
	}

	switch(sock->type) {
		case SOCK_DGRAM:
			dtlsconnect(sock);
			break;
		case SOCK_STREAM:
			sslsockstart(sock, NULL, 0);
			break;
	}
}

extern void dtlstimeout(struct fwsocket *sock, struct timeval *timeleft, int defusec) {
	if (!sock || !sock->ssl || !sock->ssl->ssl) {
		return;
	}

	objlock(sock->ssl);
	if (!DTLSv1_get_timeout(sock->ssl->ssl, timeleft)) {
		timeleft->tv_sec = 0;
		timeleft->tv_usec = defusec;
	}
	objunlock(sock->ssl);
}

extern void dtlshandltimeout(struct fwsocket *sock) {
	if (!sock->ssl) {
		return;
	}

	objlock(sock->ssl);
	DTLSv1_handle_timeout(sock->ssl->ssl);
	objunlock(sock->ssl);
}
