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

/** @file
  * @ingroup LIB-INI
  * @brief INI style config file interface.
  * @addtogroup LIB-INI
  * @{*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/dtsapp.h"

/** @brief Configuration file category*/
struct config_category {
	/** @brief Category name.*/
	const char *name;
	/** @brief Entries in category.*/
	struct bucket_list *entries;
};

/** @brief Config file.*/
struct config_file {
	/** @brief Filename.*/
	const char *filename;
	/** @brief File path.*/
	const char *filepath;
	/** @brief Categories.*/
	struct bucket_list *cat;
};

static struct bucket_list *configfiles = NULL;

static int32_t hash_files(const void *data, int key) {
	int ret;
	const struct config_file *file = data;
	const char *hashkey = (key) ? data : file->filename;

	ret = jenhash(hashkey, strlen(hashkey), 0);

	return(ret);
}

static int32_t hash_cats(const void *data, int key) {
	int ret;
	const struct config_category *cat = data;
	const char *hashkey = (key) ? data : cat->name;

	ret = jenhash(hashkey, strlen(hashkey), 0);

	return(ret);
}

static void initconfigfiles(void) {
	if (!configfiles) {
		configfiles = create_bucketlist(4, hash_files);
	}
}

/** @brief Empty out and unreference config files.*/
extern void unrefconfigfiles(void) {
	if (configfiles) {
		objunref(configfiles);
	}
}

static void free_config_entry(void *data) {
	struct config_entry *entry = data;

	if (entry->item) {
		free((void *)entry->item);
	}
	if (entry->value) {
		free((void *)entry->value);
	}
}

static void add_conf_entry(struct config_category *category, const char *item, const char *value) {
	struct config_entry *newentry;

	if (!category || !category->entries || !(newentry = objalloc(sizeof(*newentry), free_config_entry))) {
		return;
	}

	ALLOC_CONST(newentry->item, item);
	ALLOC_CONST(newentry->value, value);

	addtobucket(category->entries, newentry);
	objunref(newentry);
}

static void free_config_category(void *data) {
	struct config_category *cat = data;

	if (cat->name) {
		free((void *)cat->name);
	}
	if (cat->entries) {
		objunref(cat->entries);
	}
}

static struct config_category *create_conf_category(const char *name) {
	struct config_category *newcat;

	if (!(newcat = objalloc(sizeof(*newcat), free_config_category))) {
		return (NULL);
	}

	ALLOC_CONST(newcat->name, name);
	newcat->entries = create_bucketlist(5, hash_cats);

	return (newcat);
}

static void free_config_file(void *data) {
	struct config_file *file = data;

	if (file->filename) {
		free((void *)file->filename);
	}
	if (file->filepath) {
		free((void *)file->filepath);
	}
	if (file->cat) {
		objunref(file->cat);
	}
}

static struct config_file *create_conf_file(const char *filename, const char *filepath) {
	struct config_file *newfile;

	if (!(newfile = objalloc(sizeof(*newfile), free_config_file))) {
		return (NULL);
	}

	ALLOC_CONST(newfile->filename, filename);
	ALLOC_CONST(newfile->filepath, filepath);
	newfile->cat = create_bucketlist(4, hash_files);

	return (newfile);
}

static char *filterconf(const char *str, int minlen) {
	char *tmp, *token;

	/*trim leading and trailing white space*/
	tmp = trim(str);

	/*remove everything after the last # ignore if # is first*/
	if ((token = strrchr(tmp, '#'))) {
		if (token == tmp) {
			return NULL;
		}
		token[0] = '\0';
	}

	/*first char is #*/
	if ((token = strchr(tmp, '#')) && (token == tmp)) {
		return NULL;
	}

	/*remove ; as first char*/
	if ((token = strchr(tmp, ';')) && (token == tmp)) {
		return NULL;
	}

	/*too short*/
	if (strlen(tmp) < minlen) {
		return NULL;
	}

	return (tmp);
}

/** @brief Process a configfile into buckets
  * @param configname Name of the configuration.
  * @param configfile File to load into this configuration container.
  * @returns Zero on success.*/
extern int process_config(const char *configname, const char *configfile) {
	struct config_file *file;
	struct config_category *category = NULL;
	FILE *config;
	char line[256];
	char item[128];
	char value[128];
	char *tmp = (char *)&line;
	char *token;

	if (!configfiles) {
		initconfigfiles();
	}

	file = create_conf_file(configname, configfile);
	addtobucket(configfiles, file);

	if (!(config = fopen(file->filepath, "r"))) {
		return (-1);
	}

	while(fgets(line, sizeof(line) - 1, config)) {
		if (!(tmp = filterconf(line, 3))) {
			continue;
		}

		/*this is a new category*/
		if ((token = strchr(tmp, '[')) && (token == tmp)) {
			tmp++;
			token = strrchr(tmp, ']');
			token[0] = '\0';
			tmp = trim(tmp);
			if (!strlenzero(tmp)) {
				if (category) {
					objunref(category);
				}
				category = create_conf_category(tmp);
				addtobucket(file->cat, category);
			}
			continue;
		}

		if (sscanf(tmp, "%[^=] %*[=] %[^\n]", (char *)&item, (char *)&value) != 2) {
			continue;
		}

		if (!category) {
			category = create_conf_category("default");
			addtobucket(file->cat, category);
		}

		add_conf_entry(category, trim(item), trim(value));
	}
	fclose(config);
	if (category) {
		objunref(category);
	}
	if (file) {
		objunref(file);
	}
	return (0);
}

/** @brief Returns the catergories bucket for a config file
  * @param configname Name assigned to the config file when calling process_config().
  * @returns Categories bucketlist.*/
extern struct bucket_list *get_config_file(const char *configname) {
	struct config_file *file;

	if ((file = bucket_list_find_key(configfiles, configname))) {
		if (file->cat) {
			if (!objref(file->cat)) {
				objunref(file);
				return (NULL);
			}
			objunref(file);
			return (file->cat);
		}
		objunref(file);
	}
	return (NULL);
}

/** @brief Return a single category
  *
  * If category is NULL the category "default" is returned.
  * @param configname Name assigned to the config file when calling process_config().
  * @param category Configuration category to return or "default" if NULL.
  * @returns Bucket list containing the category.*/
extern struct bucket_list *get_config_category(const char *configname, const char *category) {
	struct bucket_list *file;
	struct config_category *cat;

	file = get_config_file(configname);
	if (category) {
		cat = bucket_list_find_key(file, category);
	} else {
		cat = bucket_list_find_key(file, "default");
	}

	objunref(file);
	if (cat) {
		if (!objref(cat->entries)) {
			objunref(cat);
			return (NULL);
		}
		objunref(cat);
		return (cat->entries);
	} else {
		return (NULL);
	}
}

/** @brief Iterate through categories returning the entries bucket
  *
  * As well as the entries returned name will be filled upto len bytes with the category name
  * @param cloop Iterator created with get_category_loop.
  * @param name Buffer where the category name is copied.
  * @param len limit the number of characters copied to len.
  * @returns Entries list for category returned in paramaater name.*/
extern struct bucket_list *get_category_next(struct bucket_loop *cloop, char *name, int len) {
	struct config_category *category;

	if (cloop && (category = next_bucket_loop(cloop))) {
		if (category->entries) {
			if (!objref(category->entries)) {
				objunref(category);
				return (NULL);
			}
			if (!strlenzero(name)) {
				strncpy(name, category->name, len);
			}
			objunref(category);
			return (category->entries);
		} else {
			objunref(category);
		}
	}
	return (NULL);
}

/** @brief Return a bucket loop to allow iterating over categories
  * @param configname Name assigned to the config file when calling process_config().
  * @returns Bucket loop iterator.*/
extern struct bucket_loop *get_category_loop(const char *configname) {
	struct bucket_loop *cloop;
	struct bucket_list *file;

	file = get_config_file(configname);
	cloop = init_bucket_loop(file);
	objunref(file);
	return (cloop);
}

static void entry_callback(void *data, void *entry_cb) {
	struct config_entry *entry = data;
	config_entrycb *cb_entry = entry_cb, callback;

	callback = *cb_entry;

	callback(entry->item, entry->value);
}

/** @brief Callback Wraper that iterates through all items calling a callback for each item.
  *
  * @see config_entrycb
  * @param entries Bucketlist of entries (from a category).
  * @param entry_cb The callback to call on each entry.*/
extern void config_entry_callback(struct bucket_list *entries, config_entrycb entry_cb) {
	bucketlist_callback(entries, entry_callback, &entry_cb);
}

static void category_callback(void *data, void *category_cb) {
	struct config_category *category = data;
	config_catcb *cb_catptr = category_cb, cb_cat;

	cb_cat = *cb_catptr;

	cb_cat(category->entries, category->name);
}

/** @brief Callback wrapper that iterates through categories calling a callback on each category.
  *
  * @see config_catcb
  * @param categories Bucketlist from a config file containing categories.
  * @param cat_cb Callback to call on each category.*/
extern void config_cat_callback(struct bucket_list *categories, config_catcb cat_cb) {
	bucketlist_callback(categories, category_callback, &cat_cb);
}

static void file_callback(void *data, void *file_cb) {
	struct config_file *file = data;
	config_filecb *cb_fileptr = file_cb, cb_file;

	cb_file = *cb_fileptr;

	cb_file(file->cat, file->filename, file->filepath);
}

/** @brief Callback wrapper to iterate over all configfiles calling a callback on each file
  *
  * @see config_filecb
  * @param file_cb Callback to call.*/
extern void config_file_callback(config_filecb file_cb) {
	bucketlist_callback(configfiles, file_callback, &file_cb);
}

/** @brief Find the entry in a config file
  * @param categories Categories bucketlist.
  * @param item Item to search for.
  * @returns Reference to a entry.*/
extern struct config_entry *get_config_entry(struct bucket_list *categories, const char *item) {
	struct config_entry *entry;

	entry = bucket_list_find_key(categories, item);

	return (entry);
}

/** @}*/
