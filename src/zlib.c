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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "include/dtsapp.h"

static void zobj_free(void *data) {
	struct zobj *zdata = data;

	if (zdata->buff) {
		free(zdata->buff);
	}
}

/*
 * return zobj containing the compressed data
 */
extern struct zobj *zcompress(uint8_t *buff, uint16_t len, uint8_t level) {
	struct zobj *ret;

	if (!(ret = objalloc(sizeof(*ret), zobj_free))) {
		return (NULL);
	}

	ret->zlen = compressBound(len);
	ret->olen = len;

	if (!(ret->buff = malloc(ret->zlen))) {
		return (NULL);
	}
	compress2(ret->buff, (uLongf*)&ret->zlen, buff, len, level);

	return (ret);
}

/*
 * uncompress data to obuff must be buff->olen big
 */
extern void zuncompress(struct zobj *buff, uint8_t *obuff) {
	uLongf olen = buff->olen;

	if (!obuff) {
		return;
	}

	uncompress(obuff, &olen, buff->buff, buff->zlen);
}
