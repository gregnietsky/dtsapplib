/** @file
  * @ingroup LIB-CURL
  * @brief CURL Interface.
  * @addtogroup LIB-CURL
  * @{*/

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "dtsapp.h"

static void *curl_isinit = NULL;
static CURL *curl = NULL;

/** @brief Allow progress monitoring.*/
static struct curl_progress {
	/** @brief data passed in callback.*/
	void *data;
	/** @brief CURL progress callback function.*/
	curl_progress_func cb;
	/** @brief Callback function to allocate data.*/
	curl_progress_newdata d_cb;
	/** @brief Callback function to pause the progress bar.*/
	curl_progress_pause p_cb;
} *curlprogress = NULL;

/** @brief CURL Authentification callback.*/
static struct curl_password {
	/** @brief Authentification callback.*/
	curl_authcb authcb;
	/** @brief Reference to data passed to callback.*/ 
	void *data;
} *curlpassword = NULL;

/** @brief HTTP post data structure.*/
struct curl_post {
	/** @brief First item in the list.*/
	struct curl_httppost *first;
	/** @brief Last item in the list.*/
	struct curl_httppost *last;
};

static size_t bodytobuffer(void *ptr, size_t size, size_t nmemb, void *userdata) {
	size_t bufsize = size * nmemb;
	struct curlbuf *mem = (struct curlbuf *)userdata;

	if (!(mem->body = realloc(mem->body, mem->bsize + bufsize + 1))) {
		return 0;
	}
	memcpy(&(mem->body[mem->bsize]), ptr, bufsize);
	mem->bsize += bufsize;
	mem->body[mem->bsize] = '\0';
	return bufsize;
}

static size_t headertobuffer(void *ptr, size_t size, size_t nmemb, void *userdata) {
	size_t bufsize = size * nmemb;
	struct curlbuf *mem = (struct curlbuf *)userdata;

	if (!(mem->header = realloc(mem->header, mem->hsize + bufsize + 1))) {
		return 0;
	}
	memcpy(&(mem->header[mem->hsize]), ptr, bufsize);
	mem->hsize += bufsize;
	mem->header[mem->hsize] = '\0';
	return bufsize;
}

static void curlfree(void *data) {
	if (curl) {
		curl_easy_cleanup(curl);
		curl = NULL;
	}
	if (curlprogress) {
		objunref(curlprogress);
		curlprogress = NULL;
	}
	if (curlpassword) {
		objunref(curlpassword);
		curlpassword = NULL;
	}
}

/** @brief Initilise the CURL library.
  * @note Curl functions will initilize and unreference curl when done
  * it is best the application hold a reference to benifit from caching.
  * curlclose() Must be called if it has been used*/
int curlinit(void) {
	if (curl_isinit) {
		return objref(curl_isinit);
	}

	if (!(curl_isinit = objalloc(sizeof(void *),curlfree))) {
		return 0;
	}

	objlock(curl_isinit);
	if (!(curl = curl_easy_init())) {
		objunlock(curl_isinit);
		objunref(curl_isinit);
		return 0;
	}

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0 [Distro Solutions]");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bodytobuffer);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headertobuffer);
	objunlock(curl_isinit);
	return 1;
}

/** @brief Un reference CURL.
  * This is required for each call to curlinit().*/
void curlclose(void) {
	objunref(curl_isinit);
	curl_isinit = NULL;
}

static void emptybuffer(void *data) {
	struct curlbuf *writebuf = data;

	if (!writebuf) {
		return;
	}

	if (writebuf->body) {
		free(writebuf->body);
	}

	if (writebuf->header) {
		free(writebuf->header);
	}

	writebuf->body = NULL;
	writebuf->header = NULL;
	writebuf->bsize = 0;
	writebuf->hsize = 0;
}

static struct curlbuf *curl_sendurl(const char *def_url, struct basic_auth *bauth, struct curl_post *post, curl_authcb authcb_in,void *auth_data_in) {
	long res;
	int i = 0;
	struct basic_auth *auth = bauth;
	struct curlbuf *writebuf;
	char userpass[64];
	char *url;
	void *p_data = NULL;
	curl_authcb authcb = authcb_in;
	void *auth_data = auth_data_in;
	/*    char buffer[1024];
	    struct curl_slist *cookies, *nc;*/

	if (!curlinit()) {
		return NULL;
	}

	if (!(writebuf = objalloc(sizeof(*writebuf), emptybuffer))) {
		objunref(curl_isinit);
		return NULL;
	}

	objlock(curl_isinit);
	curl_easy_setopt(curl, CURLOPT_URL, def_url);
	/*    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, buffer);*/

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, writebuf);
	curl_easy_setopt(curl, CURLOPT_WRITEHEADER, writebuf);

	if (post) {
		objlock(post);
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, post->first);
	}

	if (auth && auth->user && auth->passwd) {
		snprintf(userpass, 63, "%s:%s", auth->user, auth->passwd);
	   	curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		i++;
	} else if (!auth) {
		auth = curl_newauth(NULL, NULL);
	}

	if (curlprogress && ((p_data = curlprogress->d_cb(curlprogress->data)))) {
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
		curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, curlprogress->cb);
		curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, p_data);
	}

	if (curlpassword && !authcb) {
		authcb = curlpassword->authcb;
		auth_data = curlpassword->data;
	}

	do {
		if (!(res = curl_easy_perform(curl))) {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res);
			switch (res) {
				/*needs auth*/
				case 401:
					if (curlprogress && curlprogress->p_cb) {
						curlprogress->p_cb(p_data, 1);
					}
					if ((authcb) && ((auth = authcb((auth) ? auth->user : "", (auth) ? auth->passwd : "", auth_data)))) {
						snprintf(userpass, 63, "%s:%s", auth->user, auth->passwd);
						curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
						emptybuffer(writebuf);
					} else {
						i=3;
					}

					if (curlprogress && curlprogress->p_cb) {
						curlprogress->p_cb(p_data, 0);
					}
					break;
				/*not found*/
				case 300:
					i=3;
					break;
				/*redirect*/
				case 301:
					curl_easy_getinfo(curl,CURLINFO_REDIRECT_URL, &url);
					curl_easy_setopt(curl, CURLOPT_URL, url);
					emptybuffer(writebuf);
					i--;
					break;
				/*ok*/
				case 200:
					curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &writebuf->c_type);
					break;
			}
		}
		i++;
	} while ((res != 200) && (i < 3));

	/*    curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
	    for(nc = cookies; nc; nc=nc->next) {
	        printf("%s\n", nc->data);
	    }*/

	if (!bauth) {
		objunref(auth);
	}

	if (post) {
		objunlock(post);
		objunref(post);
	}

	if (curlprogress && curlprogress->p_cb) {
		curlprogress->p_cb(p_data, -1);
	}

	if (p_data) {
		objunref(p_data);
	}

	objunlock(curl_isinit);
	objunref(curl_isinit);
	return writebuf;
}

/** @brief Fetch the URL using CURL (HTTP GET)
  * @note if no authcb is specified and curl_setauth_cb() has been called this default will be used.
  * @param def_url URL to fetch.
  * @param bauth Basic auth structure to initilise auth.
  * @param authcb Callback if authentification is required.
  * @param auth_data Reference to userdata passed in auth callback.
  * @returns CURL buffer structure.*/
struct curlbuf *curl_geturl(const char *def_url, struct basic_auth *bauth, curl_authcb authcb,void *auth_data) {
	return curl_sendurl(def_url, bauth, NULL, authcb, auth_data);
}

/** @brief Fetch the URL using CURL (HTTP POST)
  * @note if no authcb is specified and curl_setauth_cb() has been called this default will be used.
  * @param def_url URL to fetch.
  * @param bauth Basic auth structure to initilise auth.
  * @param post Reference to curl post structure.
  * @param authcb Callback if authentification is required.
  * @param auth_data Reference to userdata passed in auth callback.
  * @returns CURL buffer structure.*/
struct curlbuf *curl_posturl(const char *def_url, struct basic_auth *bauth, struct curl_post *post, curl_authcb authcb,void *auth_data) {
	return curl_sendurl(def_url, bauth, post, authcb, auth_data);
}

/** @brief If the buffer contains GZIP data uncompress it.
  * @param cbuf Curl buffer to uncompress.
  * @returns Pointer to cbuf with the body replaced uncompressed.*/
struct curlbuf *curl_ungzip(struct curlbuf *cbuf) {
	uint8_t *gzbuf;
	uint32_t len;

	if (is_gzip((uint8_t *)cbuf->body, cbuf->bsize) &&
			((gzbuf = gzinflatebuf((uint8_t *)cbuf->body, cbuf->bsize, &len)))) {
		free(cbuf->body);
		cbuf->body = gzbuf;
		cbuf->bsize = len;
	}
	return cbuf;
}

static void curl_freeauth(void *data) {
	struct basic_auth *bauth = (struct basic_auth *)data;
	if (!bauth) {
		return;
	}
	if (bauth->user) {
		memset((void *)bauth->user, 0, strlen(bauth->user));
		free((void *)bauth->user);
	}
	if (bauth->passwd) {
		memset((void *)bauth->passwd, 0, strlen(bauth->passwd));
		free((void *)bauth->passwd);
	}
}

/** @brief Create a new auth structure with initial vallues
  * @note if NULL is supplied its replaced with zero length string
  * @param user Optional initial username to set.
  * @param passwd Optional initial password to set.
  * @returns Reference to new authentification structure.*/
struct basic_auth *curl_newauth(const char *user, const char *passwd) {
	struct basic_auth *bauth;

	if (!(bauth = (struct basic_auth *)objalloc(sizeof(*bauth), curl_freeauth))) {
		return NULL;
	}
	if (user) {
		bauth->user = strdup(user);
	} else {
		bauth->user = strdup("");
	}
	if (passwd) {
		bauth->passwd = strdup(passwd);
	} else {
		bauth->passwd = strdup("");
	}
	return bauth;
}

static void free_post(void *data) {
	struct curl_post *post = data;
	if (post->first) {
		curl_formfree(post->first);
	}
}

/** @brief Create a HTTP Post data structure.
  * @returns Reference to new structure.*/
extern struct curl_post *curl_newpost(void) {
	struct curl_post *post;
	if (!(post = objalloc(sizeof(*post), free_post))) {
		return NULL;
	}
	post->first = NULL;
	post->last = NULL;
	return post;
}

/** @brief Add a item value pair to post structure.
  * @param post Post structure created with curl_newpost()
  * @param name Name of the pair.
  * @param value Value of the pair.*/
void curl_postitem(struct curl_post *post, const char *name, const char *value) {
	if (!name || !value) {
		return;
	}
	objlock(post);
	curl_formadd(&post->first, &post->last,
		CURLFORM_COPYNAME, name,
		CURLFORM_COPYCONTENTS, value,
		CURLFORM_END);
	objunlock(post);
}

/** @brief Escape and return the url
  * @param url URL to escape
  * @returns A malloc()'d URL that needs to be free()'d*/
extern char *url_escape(char *url) {
	char *esc;
	char *ret = NULL;

	if (!curlinit()) {
		return NULL;
	}

	objlock(curl_isinit);
	esc = curl_easy_escape(curl, url, 0);
	if (esc) {
		ret = strdup(esc);
	}
 	curl_free(esc);
	objunlock(curl_isinit);
	objunref(curl_isinit);
	return ret;
}

/** @brief UN escape and return the url
  * @param url URL to un escape
  * @returns A malloc()'d URL that needs to be free()'d*/
extern char *url_unescape(char *url) {
	char *uesc;
	char *ret = NULL;

	if (!curlinit()) {
		return NULL;
	}

	objlock(curl_isinit);
	uesc = curl_easy_unescape(curl, url, 0, 0);
	if (uesc) {
		ret = strdup(uesc);
	}
 	curl_free(uesc);
	objunlock(curl_isinit);
	objunref(curl_isinit);
	return ret;
}

static void free_progress(void *data) {
	struct curl_progress *prg = data;
	if (prg->data) {
		objunref(prg->data);
	}
}

/** @brief Configure global progress handling
  * @note This will only persist as long as a reference to CURL is held use curlinit() and curlclose() at application startup and shutdown.
  * @param cb CURL progress function callback.
  * @param p_cb CURL progress control (pause) callback.
  * @param d_cb CURL progress data allocation callback.
  * @param data initial data passed to d_cb.
  * @see curl_progress_func()
  * @see curl_progress_pause()
  * @see curl_progress_newdata()*/
void curl_setprogress(curl_progress_func cb, curl_progress_pause p_cb, curl_progress_newdata d_cb, void *data) {
	if (curlprogress) {
		objunref(curlprogress);
		curlprogress = NULL;
	}

	if (!(curlprogress = objalloc(sizeof(*curlprogress), free_progress))) {
		return;
	}
	curlprogress->cb = cb;
	curlprogress->d_cb = d_cb;
	curlprogress->p_cb = p_cb;
	if (data && objref(data)) {
		curlprogress->data = data;
	}
}

static void free_curlpassword(void *data) {
	struct curl_password *cpwd = data;
	if (cpwd->data) {
		objunref(cpwd->data);
	}
}

/** @brief Set global password callback.
  * @note This will only persist as long as a reference to CURL is held use curlinit() and curlclose() at application startup and shutdown.
  * @param auth_cb Authentification call back.
  * @param data Reference to userdata passed in callback.*/
void curl_setauth_cb(curl_authcb auth_cb, void *data) {
	if (curlpassword) {
		objunref(curlpassword);
		curlpassword = NULL;
	}

	if (!(curlpassword = objalloc(sizeof(*curlpassword), free_curlpassword))) {
		return;
	}

	curlpassword->authcb = auth_cb;
	if (data && objref(data)) {
		curlpassword->data = data;
	}
}

/** \brief Create a XML document from from buffer (application/xml)
  * \param cbuf CURL request buffer.
  * \returns Reference to XML document.*/
extern struct xml_doc *curl_buf2xml(struct curlbuf *cbuf) {
	struct xml_doc *xmldoc = NULL;

	if (cbuf && cbuf->c_type && !strcmp("application/xml", cbuf->c_type)) {
		curl_ungzip(cbuf);
		xmldoc = xml_loadbuf(cbuf->body, cbuf->bsize, 1);
	}
	return xmldoc;
}

/** @}*/

