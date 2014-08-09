/** @file
  * @ingroup LIB-XSLT
  * @brief XSLT Interface.
  * @addtogroup LIB-XSLT
  * @{*/

#include <stdint.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <windows.h>
#endif
#include <string.h>

#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>

#include "include/dtsapp.h"
#include "include/priv_xml.h"

/** @brief XSLT Document.*/
struct xslt_doc {
	/** @brief Pointer to the document.*/
	xsltStylesheetPtr doc;
	/** @brief Bucket list of paramaters to apply to the document.*/
	struct bucket_list *params;
};

/** @brief XSLT Parameter name/value pair.*/
struct xslt_param {
	/** @brief Name of paramater.*/
	const char *name;
	/** @brief value of paramater.*/
	const char *value;
};

static void *xslt_has_init_parser = NULL;

static void free_xsltdoc(void *data) {
	struct xslt_doc *xsltdoc = data;

	xsltFreeStylesheet(xsltdoc->doc);
	objunref(xsltdoc->params);
	xslt_close();
}

static void free_parser(void *data) {
	xsltCleanupGlobals();
	xmlCleanupParser();
}

static int32_t xslt_hash(const void *data, int key) {
	int ret;
	const struct xslt_param *xp = data;
	const char *hashkey = (key) ? data : xp->name;

	if (hashkey) {
		ret = jenhash(hashkey, strlen(hashkey), 0);
	} else {
		ret = jenhash(xp, sizeof(xp), 0);
	}
	return(ret);
}

/** @brief Open a XSLT file returning reference to it.
  * @param xsltfile XSLT pathname to open.
  * @returns Reference to XSLT document.*/
extern struct xslt_doc *xslt_open(const char *xsltfile) {
	struct xslt_doc *xsltdoc;

	if (!(xsltdoc = objalloc(sizeof(*xsltdoc), free_xsltdoc))) {
		return NULL;
	}
	xslt_init();

	xsltdoc->doc = xsltParseStylesheetFile((const xmlChar *)xsltfile);
	xsltdoc->params = create_bucketlist(0, xslt_hash);
	return xsltdoc;
}

static void free_param(void *data) {
	struct xslt_param *param = data;
	if (param->name) {
		free((void *)param->name);
	}
	if (param->value) {
		free((void *)param->value);
	}
}

/** @brief Add a parameter to the XSLT document.
  * @param xsltdoc Reference to XSLT document.
  * @param param Name of parameter.
  * @param value Parameter value.*/
extern void xslt_addparam(struct xslt_doc *xsltdoc, const char *param, const char *value) {
	struct xslt_param *xparam;
	int size;

	if (!xsltdoc || !xsltdoc->params || !objref(xsltdoc) || !(xparam = objalloc(sizeof(*xparam), free_param))) {
		return;
	}

	size = strlen(value) + 3;
	ALLOC_CONST(xparam->name, param);
	xparam->value = malloc(size);
	snprintf((char *)xparam->value, size, "'%s'", value);
	objlock(xsltdoc);
	addtobucket(xsltdoc->params, xparam);
	objunlock(xsltdoc);
	objunref(xparam);
	objunref(xsltdoc);
}

/** @brief Delete all parameters of a XSLT document.
  * @param xsltdoc Reference to XSLT document.*/
void xslt_clearparam(struct xslt_doc *xsltdoc) {
	if (!xsltdoc || !xsltdoc->params) {
		return;
	}

	objlock(xsltdoc);
	objunref(xsltdoc->params);
	xsltdoc->params = create_bucketlist(0, xslt_hash);
	objunlock(xsltdoc);
}

/* grabs ref to xmldoc/xsltdoc and locks xsltdoc*/
static const char **xslt_params(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc) {
	const char **params = NULL;
	struct xslt_param *xparam;
	struct bucket_loop *bloop;
	int cnt=0;

	if (!objref(xmldoc)) {
		return NULL;
	}

	if (!objref(xsltdoc)) {
		objunref(xmldoc);
		return NULL;
	}

	objlock(xsltdoc);
	if (!(params = malloc(sizeof(void *) * (bucket_list_cnt(xsltdoc->params)*2 + 2)))) {
		objunlock(xsltdoc);
		objunref(xsltdoc);
		objunref(xmldoc);
		return NULL;
	}

	bloop = init_bucket_loop(xsltdoc->params);
	while(bloop && (xparam = next_bucket_loop(bloop))) {
		params[cnt] = xparam->name;
		cnt++;
		params[cnt] = xparam->value;
		cnt++;
		objunref(xparam);
	};
	params[cnt] = NULL;
	return params;
}

/** @brief Apply XSLT document to a XML document.
  * @param xmldoc Reference to XML document.
  * @param xsltdoc Reference to XSLT document.
  * @param filename File to write the result too.
  * @param comp Compression level 0-9 [0 = none].*/
extern void xslt_apply(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc, const char *filename, int comp) {
	const char **params = NULL;
	xmlDocPtr res;

	/* ref's xml/xslt locks xslt IF set*/
	if (!(params = xslt_params(xmldoc, xsltdoc))) {
		return;
	}

#ifndef __WIN32__
	touch(filename, 80, 80);
#else
	touch(filename);
#endif
	objlock(xmldoc);
	res = xsltApplyStylesheet(xsltdoc->doc, xmldoc->doc, params);
	xsltSaveResultToFilename(filename, res, xsltdoc->doc, comp);
	objunlock(xmldoc);
	objunref(xmldoc);
	objunlock(xsltdoc);

	free(params);
	xmlFreeDoc(res);
	xslt_clearparam(xsltdoc);
	objunref(xsltdoc);
}

/** @brief Apply XSLT document to a XML document returning result in buffer.
  * @param xmldoc Reference to XML document.
  * @param xsltdoc Reference to XSLT document.
  * @returns Reference to xml_buffer containing the result of the transform.*/
extern void *xslt_apply_buffer(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc) {
	struct xml_buffer *xmlbuf;
	const char **params;
	xmlDocPtr res;

	if (!(xmlbuf = objalloc(sizeof(*xmlbuf),xml_free_buffer))) {
		return NULL;
	}

	if (!(params = xslt_params(xmldoc, xsltdoc))) {
		objunref(xmlbuf);
		return NULL;
	}

	objlock(xmldoc);
	res = xsltApplyStylesheet(xsltdoc->doc, xmldoc->doc, params);
	xsltSaveResultToString(&xmlbuf->buffer, &xmlbuf->size, res, xsltdoc->doc);
	objunlock(xmldoc);
	objunref(xmldoc);
	objunlock(xsltdoc);

	free(params);
	xmlFreeDoc(res);
	xslt_clearparam(xsltdoc);
	objunref(xsltdoc);

	return xmlbuf;
}

/** @brief Reference the XSLT parser.
  * @note It is best if the application keeps a reference to the parser before use of XSLT and
  * release it on termination.*/
extern void xslt_init() {
	if (!xslt_has_init_parser) {
		xslt_has_init_parser=objalloc(0, free_parser);
	} else {
		objref(xslt_has_init_parser);
	}
}

/** @brief Release reference to XSLT parser.
  * @note It is best if the application keeps a reference to the parser before use of XSLT and
  * release it on termination.*/
extern void xslt_close() {
	if (xslt_has_init_parser) {
		objunref(xslt_has_init_parser);
	}
}

/** @}*/
