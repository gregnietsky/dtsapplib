/*
    Distrotech Solutions wxWidgets Gui Interface
    Copyright (C) 2013 Gregory Hinton Nietsky <gregory@distrotech.co.za>

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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>

extern int is_file(const char *path) {
	struct stat sr;
	if (!stat(path, &sr)) {
		return 1;
	} else {
		return 0;
	}
}

extern int is_dir(const char *path) {
	struct stat sr;
	if (!stat(path, &sr) && S_ISDIR(sr.st_mode)) {
		return 1;
	} else {
		return 0;
	}
}

extern int is_exec(const char *path) {
	struct stat sr;
	if (!stat(path, &sr) && (S_IXUSR & sr.st_mode)) {
		return 1;
	} else {
		return 0;
	}
}

extern int mk_dir(const char *dir, mode_t mode, uid_t user, gid_t group) {
	struct stat sr;

	if ((stat(dir, &sr) && (errno == ENOENT)) && !mkdir(dir, mode) && !chown(dir, user, group)) {
		return 0;
	}
	return -1;
}
