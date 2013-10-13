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

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

/** @defgroup LIB-Util Micelaneous utilities.
  * @brief Utilities commonly used
  *
  * @ingroup LIB
  * @addtogroup LIB-Util
  * @{
  * @file
  * @brief Utilities commonly used
  *
  * @n @verbatim
 * Acknowledgments [MD5 HMAC http://www.ietf.org/rfc/rfc2104.txt]
 *      Pau-Chen Cheng, Jeff Kraemer, and Michael Oehler, have provided
 *      useful comments on early drafts, and ran the first interoperability
 *      tests of this specification. Jeff and Pau-Chen kindly provided the
 *      sample code and test vectors that appear in the appendix.  Burt
 *      Kaliski, Bart Preneel, Matt Robshaw, Adi Shamir, and Paul van
 *      Oorschot have provided useful comments and suggestions during the
 *      investigation of the HMAC construction.
 *
@endverbatim*/

#ifdef __WIN32__
#include <winsock2.h>
#include <windows.h>
#endif

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "include/dtsapp.h"

/** @brief Seed openssl random number generator
  *
  * This should be run at application startup
  * @todo This wont work on WIN32*/
extern void seedrand(void) {
	int fd = open("/dev/random", O_RDONLY);
	int len;
	char    buf[64];

	len = read(fd, buf, 64);
	RAND_seed(buf, len);
}

/** @brief Generate random sequence
  *
  * @param buf Buffer to write random data.
  * @param len Length to write.
  * @return 1 on success 0 otherwise.*/
extern int genrand(void *buf, int len) {
	return (RAND_bytes(buf, len));
}

/** @brief Calculate the SHA2-512 hash accross 2 data chunks.
  *
  * @param buff buffer to place the hash (64 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.
  * @param data2 Second data chunk to calculate.
  * @param len2 Length of data2.*/
extern void sha512sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2) {
	SHA512_CTX c;

	SHA512_Init(&c);
	SHA512_Update(&c, data, len);
	if (data2) {
		SHA512_Update(&c, data2, len2);
	}
	SHA512_Final(buff, &c);
}

/** @brief Calculate the SHA2-512 hash
  *
  * @param buff buffer to place the hash (64 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.*/
extern void sha512sum(unsigned char *buff, const void *data, unsigned long len) {
	sha512sum2(buff, data, len, NULL, 0);
}


/** @brief Calculate the SHA2-256 hash accross 2 data chunks.
  *
  * @param buff buffer to place the hash (32 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.
  * @param data2 Second data chunk to calculate.
  * @param len2 Length of data2.*/
extern void sha256sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2) {
	SHA256_CTX c;

	SHA256_Init(&c);
	SHA256_Update(&c, data, len);
	if (data2) {
		SHA256_Update(&c, data2, len2);
	}
	SHA256_Final(buff, &c);
}

/** @brief Calculate the SHA2-256 hash
  *
  * @param buff buffer to place the hash (32 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.*/
extern void sha256sum(unsigned char *buff, const void *data, unsigned long len) {
	sha256sum2(buff, data, len, NULL, 0);
}

/** @brief Calculate the SHA1 hash accross 2 data chunks.
  *
  * @param buff buffer to place the hash (20 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.
  * @param data2 Second data chunk to calculate.
  * @param len2 Length of data2.*/
extern void sha1sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2) {
	SHA_CTX c;

	SHA_Init(&c);
	SHA_Update(&c, data, len);
	if (data2) {
		SHA_Update(&c, data2, len2);
	}
	SHA_Final(buff, &c);
}

/** @brief Calculate the SHA1 hash
  *
  * @param buff buffer to place the hash (20 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.*/
extern void sha1sum(unsigned char *buff, const void *data, unsigned long len) {
	sha1sum2(buff, data, len, NULL, 0);
}

/** @brief Calculate the MD5 hash accross 2 data chunks.
  *
  * @param buff buffer to place the hash (16 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.
  * @param data2 Second data chunk to calculate.
  * @param len2 Length of data2.*/
extern void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2) {
	MD5_CTX c;

	MD5_Init(&c);
	MD5_Update(&c, data, len);
	if (data2) {
		MD5_Update(&c, data2, len2);
	}
	MD5_Final(buff, &c);
}

/** @brief Calculate the MD5 hash
  *
  * @param buff buffer to place the hash (16 bytes).
  * @param data First data chunk to calculate.
  * @param len Length of data.*/
extern void md5sum(unsigned char *buff, const void *data, unsigned long len) {
	md5sum2(buff, data, len, NULL, 0);
}

static int _digest_cmp(unsigned char *md51, unsigned char *md52, int len) {
	int cnt;
	int chk = 0;

	for(cnt = 0; cnt < len; cnt ++) {
		chk += md51[cnt] & ~md52[cnt];
	}

	return (chk);
}

/** @brief Compare two md5 hashes
  *
  * @param digest1 Digest to compare.
  * @param digest2 Digest to compare.
  * @return 0 on equality.*/
extern int md5cmp(unsigned char *digest1, unsigned char *digest2) {
	return (_digest_cmp(digest1, digest2, 16));
}

/** @brief Compare two SHA1 hashes
  *
  * @param digest1 Digest to compare.
  * @param digest2 Digest to compare.
  * @return 0 on equality.*/
extern int sha1cmp(unsigned char *digest1, unsigned char *digest2) {
	return (_digest_cmp(digest1, digest2, 20));
}

/** @brief Compare two SHA2-256 hashes
  *
  * @param digest1 Digest to compare.
  * @param digest2 Digest to compare.
  * @return 0 on equality.*/
extern int sha256cmp(unsigned char *digest1, unsigned char *digest2) {
	return (_digest_cmp(digest1, digest2, 32));
}

/** @brief Compare two SHA2-512 hashes
  *
  * @param digest1 Digest to compare.
  * @param digest2 Digest to compare.
  * @return 0 on equality.*/
extern int sha512cmp(unsigned char *digest1, unsigned char *digest2) {
	return (_digest_cmp(digest1, digest2, 64));
}

static void _hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen,
			void (*func)(unsigned char *, const void *, unsigned long, const void *, unsigned long), short alglen) {
	unsigned char	okey[64], ikey[64];
	int		bcnt;

	memset(ikey, 0, 64);
	memset(okey, 0, 64);

	if (klen < 64) {
		memcpy(ikey, key, klen);
		memcpy(okey, key, klen);
	} else {
		md5sum(okey, key, klen);
		memcpy(ikey, okey, klen);
	}

	for (bcnt = 0; bcnt < 64; bcnt++) {
		ikey[bcnt] ^= 0x36;
		okey[bcnt] ^= 0x5c;
	};

	func(buff, ikey, 64, data, len);
	func(buff, okey, 64, buff, alglen);
}

/** @brief Hash Message Authentication Codes (HMAC) MD5
  *
  * @param buff HMAC returned in this buffer (16 bytes).
  * @param data Data to sign.
  * @param len Length of data.
  * @param key Key to signwith.
  * @param klen Length of key.*/
extern void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen) {
	_hmac(buff, data, len, key, klen, md5sum2, 16);
}

/** @brief Hash Message Authentication Codes (HMAC) SHA1
  *
  * @param buff HMAC returned in this buffer (20 bytes).
  * @param data Data to sign.
  * @param len Length of data.
  * @param key Key to signwith.
  * @param klen Length of key.*/
extern void sha1hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen) {
	_hmac(buff, data, len, key, klen, sha1sum2, 20);
}

/** @brief Hash Message Authentication Codes (HMAC) SHA2-256
  *
  * @param buff HMAC returned in this buffer (32 bytes).
  * @param data Data to sign.
  * @param len Length of data.
  * @param key Key to signwith.
  * @param klen Length of key.*/
extern void sha256hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen) {
	_hmac(buff, data, len, key, klen, sha256sum2, 32);
}

/** @brief Hash Message Authentication Codes (HMAC) SHA2-512
  *
  * @param buff HMAC returned in this buffer (64 bytes).
  * @param data Data to sign.
  * @param len Length of data.
  * @param key Key to signwith.
  * @param klen Length of key.*/
extern void sha512hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen) {
	_hmac(buff, data, len, key, klen, sha512sum2, 64);
}

/** @brief Check if a string is zero length
  *
  * strlen can not be used on a NULL string this
  * is a quick and dirty util to check it.
  * @param str String to check.
  * @return 1 if the string is null or zero length*/
extern int strlenzero(const char *str) {
	if (str && strlen(str)) {
		return (0);
	}
	return (1);
}


/** @brief Trim white space at the begining of a string.
  *
  * @param str String to trim.
  * @return Pointer to trimed string.*/
extern char *ltrim(char *str) {
	char *cur = str;

	if (strlenzero(str)) {
		return (str);
	}

	while(isspace(cur[0])) {
		cur++;
	}

	return (cur);
}


/** @brief Trim white space at the end of a string.
  *
  * @param str String to trim.
  * @return Pointer to trimed string.*/
extern char *rtrim(const char *str) {
	int len;
	char *cur = (char *)str;

	if (strlenzero(str)) {
		return (cur);
	}

	len = strlen(str) - 1;
	while(len && isspace(cur[len])) {
		cur[len] = '\0';
		len--;
	}

	return (cur);
}

/** @brief Trim whitesapce from the beggining and end of a string.
  *
  * @param str String to trim.
  * @return Trimed string.*/
extern char *trim(const char *str) {
	char *cur = (char *)str;

	cur = ltrim(cur);
	cur = rtrim(cur);
	return (cur);
}

/** @brief Convert a timeval struct to 64bit NTP time.
  *
  * @param tv Timeval struct to convert.
  * @return 64 bit NTP time value.*/
extern uint64_t tvtontp64(struct timeval *tv) {
	return ((((uint64_t)tv->tv_sec + 2208988800u) << 32) + ((uint32_t)tv->tv_usec * 4294.967296));
}

/*
 * RFC 1701 Checksum based on code from the RFC
 */
static uint16_t _checksum(const void *data, int len, const uint16_t check) {
	uint64_t csum = 0;
	const uint32_t *arr = (uint32_t *)data;

	/*handle 32bit chunks*/
	while(len > 3) {
		csum += *arr++;
		len -= 4;
	}

	/*handle left over 16 bit chunk*/
	if (len > 1) {
		csum += *(uint16_t *)arr;
		arr = (uint32_t *)((uint16_t *)arr + 1);
		len -= 2;
	}

	/*handle odd byte*/
	if (len) {
		csum += *(uint8_t *)arr;
	}

	/*add checksum when called as verify*/
	if (check) {
		csum += check;
	}

	/*collapse to 16 bits adding all overflows leaving 16bit checksum*/
	while(csum >> 16) {
		csum = (csum & 0xffff) + (csum >> 16);
	}

	return (~(uint16_t)csum);
}

/** @brief Obtain the checksum for a buffer.
  *
  * @param data Buffer to create checksum of.
  * @param len Buffer length.
  * @return Chechsum of data.*/
extern uint16_t checksum(const void *data, int len) {
	return (_checksum(data, len, 0));
}


/** @brief Obtain the checksum for a buffer adding a checksum
  *
  * @param checksum Checksum to add to generated checksum.
  * @param data Buffer to create checksum of.
  * @param len Buffer length.
  * @return Chechsum of data.*/
extern uint16_t checksum_add(const uint16_t checksum, const void *data, int len) {
	return (_checksum(data, len, ~checksum));
}

/** @brief Verify a checksum
  *
  * @param data Data to generate checksum.
  * @param len Length of data.
  * @param check Checksum to check against.
  * @returns 0 when checksum is verified.*/
extern uint16_t verifysum(const void *data, int len, const uint16_t check) {
	return (_checksum(data, len, check));
}

/** @brief Create a file and set user and group
  *
  * @todo WIN32 does not use uid/gid and move to file utils module.
  * @param filename File to create.
  * @param user User ID to set ownership.
  * @param group Group ID to set ownership.*/
#ifndef __WIN32__
extern void touch(const char *filename, uid_t user, gid_t group) {
	int res;
#else
extern void touch(const char *filename) {
#endif
	int fd;

	fd = creat(filename, 0600);
	close(fd);
#ifndef __WIN32__
	res = chown(filename, user, group);
	res++;
#endif
	return;
}

/** @brief Base 64 encode a buffer
  *
  * @param message Buffer to encode.
  * @param len Length of the buffer.
  * @param nonl Encode the data all on one line if non zero.
  * @return Reference to base64 encoded string.*/
extern char *b64enc_buf(const char *message, uint32_t len, int nonl) {
	BIO *bmem, *b64;
	BUF_MEM *ptr;
	char *buffer;
	double encodedSize;

	encodedSize = 1.36*len;
	buffer = objalloc(encodedSize+1, NULL);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	if (nonl) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	BIO_write(b64, message, len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &ptr);

	buffer = objalloc(ptr->length+1, NULL);
	memcpy(buffer, ptr->data, ptr->length);


	BIO_free_all(b64);

	return buffer;
}

/** @brief Base 64 encode a string
  *
  * @param message String to encode.
  * @param nonl Encode the data all on one line if non zero.
  * @return Reference to base64 encoded string.*/
extern char *b64enc(const char *message, int nonl) {
	return b64enc_buf(message, strlen(message), nonl);
}

/** @}*/
