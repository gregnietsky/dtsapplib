#include <ldap.h>
#include <ldap_schema.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <stdarg.h>

#include "include/dtsapp.h"

/*
 * http://www.opensource.apple.com/source/OpenLDAP/OpenLDAP-186/OpenLDAP/libraries/liblutil/sasl.c
 */

struct sasl_defaults {
	const char *mech;
	const char *realm;
	const char *authcid;
	const char *passwd;
	const char *authzid;
};

struct ldap_simple {
	const char *dn;
	struct berval *cred;
};

struct ldap_conn {
	LDAP	*ldap;
	char	*uri;
	int	timelim;
	int	limit;
	LDAPControl **sctrlsp;
	struct sasl_defaults *sasl;
	struct ldap_simple *simple;
};

struct ldap_modify {
	const char *dn;
	struct bucket_list *bl[3];
};

struct ldap_add {
	const char *dn;
	struct bucket_list *bl;
};

struct ldap_modval {
	const char *value;
	struct ldap_modval *next;
};

struct ldap_modreq {
	const char *attr;
	int cnt;
	struct ldap_modval *first;
	struct ldap_modval *last;
};

int ldap_count(LDAP *ld, LDAPMessage *message, int *err);
struct ldap_entry *ldap_getent(LDAP *ld, LDAPMessage **msgptr, LDAPMessage *result, int b64enc, int *err);
int dts_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in );

void free_simple(void *data) {
	struct ldap_simple *simple = data;
	struct berval *bv = simple->cred;

	if (bv && bv->bv_val) {
		free(bv->bv_val);
	}
	if (bv) {
		free(bv);
	}
	if (simple->dn) {
		free((void*)simple->dn);
	}
}

void free_modval(void *data) {
	struct ldap_modval *modv = data;

	if (modv->value) {
		free((void*)modv->value);
	}
}

void free_modreq(void *data) {
	struct ldap_modreq *modr = data;
	struct ldap_modval *modv;

	if (modr->attr) {
		free((void*)modr->attr);
	}
	for(modv = modr->first; modv; modv = modv->next) {
		objunref(modv);
	}
}

void free_modify(void *data) {
	struct ldap_modify *lmod = data;
	int cnt;
	if (lmod->dn) {
		free((void*)lmod->dn);
	}

	for(cnt=0; cnt < 3;cnt++) {
		if (lmod->bl[cnt]) {
			objunref(lmod->bl[cnt]);
		}
	}
}

void free_add(void *data) {
	struct ldap_add *lmod = data;

	if (lmod->dn) {
		free((void*)lmod->dn);
	}

	if (lmod->bl) {
		objunref(lmod->bl);
	}
}

void free_sasl(void *data) {
	struct sasl_defaults *sasl = data;

	if (sasl->mech) {
		free((void*)sasl->mech);
	}
	if (sasl->realm) {
		free((void*)sasl->realm);
	}
	if (sasl->authcid) {
		free((void*)sasl->authcid);
	}
	if (sasl->passwd) {
		free((void*)sasl->passwd);
	}
	if (sasl->authzid) {
		free((void*)sasl->authzid);
	}
}

void free_ldapconn(void *data) {
	struct ldap_conn *ld = data;


	if (ld->uri) {
		free(ld->uri);
	}
	if (ld->ldap) {
		ldap_unbind_ext_s(ld->ldap, ld->sctrlsp, NULL);
	}
	if (ld->sasl) {
		objunref(ld->sasl);
	}
	if (ld->simple) {
		objunref(ld->simple);
	}
}

void free_result(void *data) {
	struct ldap_results *res = data;
	if (res->entries) {
		objunref(res->entries);
	}
}

void free_entry(void *data) {
	struct ldap_entry *ent = data;
	struct ldap_attr *la;

	if (ent->prev) {
		ent->prev->next = ent->next;
	}
	if (ent->next) {
		ent->next->prev = ent->prev;
	}

	if (ent->dn) {
		ldap_memfree((void*)ent->dn);
	}
	if (ent->rdn) {
		objunref(ent->rdn);
	}
	if (ent->dnufn) {
		free((void*)ent->dnufn);
	}
	if (ent->attrs) {
		objunref(ent->attrs);
	}
	if (ent->first_attr) {
		for(la = ent->first_attr; la; la = la->next) {
			objunref(la);
		}
	}
}

void free_rdnarr(void *data) {
	struct ldap_rdn **rdn = data;

	for(; *rdn; rdn++) {
		objunref(*rdn);
	}
}

void free_rdn(void *data) {
	struct ldap_rdn *rdn = data;

	if (rdn->name) {
		objunref((void*)rdn->name);
	}
	if (rdn->value) {
		objunref((void*)rdn->value);
	}
}

void free_attr(void *data) {
	struct ldap_attr *la = data;
	if (la->next) {
		la->next->prev = la->prev;
	}
	if (la->prev) {
		la->prev->next = la->next;
	}
	ldap_memfree((char*)la->name);
	if (la->vals) {
		objunref(la->vals);
	}
}

void free_attrvalarr(void *data) {
	struct ldap_attrval **av = data;
	for(;*av;av++) {
		objunref(*av);
	}
}

void free_attrval(void *data) {
	struct ldap_attrval *av = data;
	if (av->buffer) {
		objunref(av->buffer);
	}
}

void free_entarr(void *data) {
	struct ldap_entry **entarr = data;

	for(;*entarr;entarr++) {
		objunref(*entarr);
	}
}

int modify_hash(const void *data, int key) {
        int ret;
        const struct ldap_modreq *modr = data;
        const char* hashkey = (key) ? data : modr->attr;

        if (hashkey) {
                ret = jenhash(hashkey, strlen(hashkey), 0);
        } else { 
                ret = jenhash(modr, sizeof(modr), 0);
        }
        return(ret);
}

int ldap_rebind_proc(LDAP *ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *params) {
	struct ldap_conn *ldap = params;
	int res = LDAP_UNAVAILABLE;

	if (!objref(ldap)) {
		return LDAP_UNAVAILABLE;
	}

	if (ldap->sasl) {
		int sasl_flags = LDAP_SASL_AUTOMATIC | LDAP_SASL_QUIET;
		struct sasl_defaults *sasl = ldap->sasl;

		res = ldap_sasl_interactive_bind_s(ld, NULL, sasl->mech, ldap->sctrlsp , NULL, sasl_flags, dts_sasl_interact, sasl);
	} else if (ldap->simple) {
		struct ldap_simple *simple = ldap->simple;

		res = ldap_sasl_bind_s(ld, simple->dn, LDAP_SASL_SIMPLE, simple->cred, ldap->sctrlsp, NULL, NULL);
	}

	objunref(ldap);
	return res;
}

extern struct ldap_conn *ldap_connect(const char *uri, enum ldap_starttls starttls, int timelimit, int limit, int debug, int *err) {
	struct ldap_conn *ld;
	int version = 3;
	int res, sslres;
	struct timeval timeout;

	if (!(ld = objalloc(sizeof(*ld), free_ldapconn))) {
		return NULL;
	}

	ld->uri = strdup(uri);
	ld->sctrlsp = NULL;
	ld->timelim = timelimit;
	ld->limit = limit;
	ld->sasl = NULL;

	if ((res = ldap_initialize(&ld->ldap, ld->uri) != LDAP_SUCCESS)) {
		objunref(ld);
		ld = NULL;
	} else {
		if (debug) {
			ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
			ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &debug);
		}
		if (timelimit) {
			timeout.tv_sec = timelimit;
			timeout.tv_usec = 0;
			ldap_set_option(ld->ldap, LDAP_OPT_NETWORK_TIMEOUT, (void*)&timeout);
		}
		ldap_set_option(ld->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
		ldap_set_option(ld->ldap, LDAP_OPT_REFERRALS, (void *)LDAP_OPT_ON);
		ldap_set_rebind_proc(ld->ldap, ldap_rebind_proc, ld);

		if ((starttls != LDAP_STARTTLS_NONE) & !ldap_tls_inplace(ld->ldap) && (sslres = ldap_start_tls_s(ld->ldap, ld->sctrlsp, NULL))) {
			if (starttls == LDAP_STARTTLS_ENFORCE) {
				objunref(ld);
				ld = NULL;
				res = sslres;
			}
		}
	}
	*err = res;
	return ld;
}

static int interaction(unsigned flags, sasl_interact_t *interact, struct sasl_defaults *defaults) {
	const char *res = interact->defresult;

	switch( interact->id ) {
		case SASL_CB_GETREALM:
			if (defaults->realm) {
				res = defaults->realm;
			}
			break;
		case SASL_CB_AUTHNAME:
			if (defaults->authcid) {
				res = defaults->authcid;
			}
			break;
		case SASL_CB_PASS:
			if (defaults->passwd) {
				res = defaults->passwd;
			}
			break;
		case SASL_CB_USER:
			if (defaults->authzid) {
				res = defaults->authzid;
			}
			break;
	}

	interact->result = (res) ? res : "";
	interact->len = strlen(interact->result);

	return LDAP_SUCCESS;
}

int dts_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in ) {
	sasl_interact_t *interact = in;

	if (!ld) {
		return LDAP_PARAM_ERROR;
	}

	while( interact->id != SASL_CB_LIST_END ) {
		int rc = interaction(flags, interact, defaults);
		if (rc)  {
			return rc;
		}
		interact++;
	}	
	return LDAP_SUCCESS;
}

extern int ldap_simplebind(struct ldap_conn *ld, const char *dn, const char *passwd) {
	struct ldap_simple *simple;
	struct berval *cred;
	int res, len = 0;

	if (!objref(ld)) {
		return LDAP_UNAVAILABLE;
	}

	if (passwd) {
		len = strlen(passwd);
	}	
	simple = objalloc(sizeof(*simple), free_simple);
	cred = calloc(sizeof(*cred), 1);
	cred->bv_val = malloc(len);
	memcpy(cred->bv_val, passwd, len);
	cred->bv_len=len;
	simple->cred = cred;
	simple->dn = strdup(dn);

	objlock(ld);
	if (ld->simple) {
		objunref(ld->simple);
	}
	ld->simple = simple;
	res = ldap_sasl_bind_s(ld->ldap, simple->dn, LDAP_SASL_SIMPLE, simple->cred, ld->sctrlsp, NULL, NULL);
	objunlock(ld);
	objunref(ld);
	return res;
}

extern int ldap_simplerebind(struct ldap_conn *ldap, const char *initialdn, const char* initialpw, const char *base, const char *filter,
                                        const char *uidrdn, const char *uid, const char *passwd) {
	int res, flen;
	struct ldap_results *results;
	const char *sfilt;

	if (!objref(ldap)) {
		return LDAP_UNAVAILABLE;
	}

	if ((res = ldap_simplebind(ldap, initialdn, initialpw))) {
		objunref(ldap);
		return res;
	}

	flen=strlen(uidrdn) + strlen(filter) + strlen(uid) + 7;
	sfilt = malloc(flen);
	snprintf((char*)sfilt, flen, "(&(%s=%s)%s)", uidrdn, uid, filter);

	if (!(results = ldap_search_sub(ldap, base, sfilt, 0, &res, uidrdn, NULL))) {
		free((void*)sfilt);
		objunref(ldap);
		return res;
	}
	free((void*)sfilt);

	if (results->count != 1) {
		objunref(results);
		objunref(ldap);
		return LDAP_INAPPROPRIATE_AUTH;
	}

	res = ldap_simplebind(ldap, results->first_entry->dn, passwd);
	objunref(ldap);
	objunref(results);
	return res;
}

extern int ldap_saslbind(struct ldap_conn *ld, const char *mech, const char *realm, const char *authcid,
				const char *passwd, const char *authzid ) {
	struct sasl_defaults *sasl;
	int res, sasl_flags = LDAP_SASL_AUTOMATIC | LDAP_SASL_QUIET;

	if (!objref(ld)) {
		return LDAP_UNAVAILABLE;
	}

	if (!(sasl = objalloc(sizeof(*sasl), free_sasl))) {
		return LDAP_NO_MEMORY;
	}

	ALLOC_CONST(sasl->passwd, passwd);

	if (mech) {
		ALLOC_CONST(sasl->mech, mech);
	} else {
		ldap_get_option(ld->ldap, LDAP_OPT_X_SASL_MECH, &sasl->mech);
	}

	if (realm) {
		ALLOC_CONST(sasl->realm, realm);
	} else {
		ldap_get_option(ld->ldap, LDAP_OPT_X_SASL_REALM, &sasl->realm );
	}

	if (authcid) {
		ALLOC_CONST(sasl->authcid, authcid);
	} else {
		ldap_get_option(ld->ldap, LDAP_OPT_X_SASL_AUTHCID, &sasl->authcid );
	}

	if (authzid) {
		ALLOC_CONST(sasl->authzid, authzid);
	} else {
		ldap_get_option(ld->ldap, LDAP_OPT_X_SASL_AUTHZID, &sasl->authzid );
	}

	objlock(ld);
	if (ld->sasl) {
		objunref(ld->sasl);
	}
	ld->sasl = sasl;
	res = ldap_sasl_interactive_bind_s(ld->ldap, NULL, sasl->mech, ld->sctrlsp , NULL, sasl_flags, dts_sasl_interact, sasl);
	objunlock(ld);
	objunref(ld);
	return res;
}

extern void ldap_close(struct ldap_conn *ld) {
	objunref(ld);
}

extern const char *ldap_errmsg(int res) {
	return ldap_err2string(res);
}

int searchresults_hash(const void *data, int key) {
        int ret;
        const struct ldap_entry *ent = data;
        const char* hashkey = (key) ? data : ent->dn;

        if (hashkey) {
                ret = jenhash(hashkey, strlen(hashkey), 0);
        } else { 
                ret = jenhash(ent, sizeof(ent), 0);
        }
        return(ret);
}

struct ldap_results *dts_ldapsearch(struct ldap_conn *ld, const char *base, int scope, const char *filter, char *attrs[], int b64enc, int *err) {
	struct timeval timeout = {0,0};
	struct ldap_results *results;
	struct ldap_entry *lent, *prev = NULL;
	LDAPMessage *result, *message = NULL;
	int res = LDAP_SUCCESS;

	if (!objref(ld)) {
		if (err) {
			*err = LDAP_UNAVAILABLE;
		}
		if (attrs) {
			free(attrs);
		}
		return NULL;
	}

	if ((results = objalloc(sizeof(*results), free_result))) {
		results->entries = create_bucketlist(4, searchresults_hash);
	}

	timeout.tv_sec = ld->timelim;
	timeout.tv_usec = 0;

	objlock(ld);
	if (!results || !results->entries ||
	    (res = ldap_search_ext_s(ld->ldap, base, scope, filter, attrs, 0, ld->sctrlsp, NULL, &timeout, ld->limit, &result))) {
		objunlock(ld);
		objunref(ld);
		objunref(results);
		ldap_msgfree(result);
		if (err) {
			*err = (!results || !results->entries) ? LDAP_NO_MEMORY : res;
		}
		if (attrs) {
			free(attrs);
		}
		return NULL;
	}
	objunlock(ld);

	if (attrs) {
		free(attrs);
	}

	if ((results->count = ldap_count(ld->ldap, result, err)) < 0) {
		objunref(ld);
		objunref(results);
		ldap_msgfree(result);
		return NULL;	
	}

	while((lent = ldap_getent(ld->ldap, &message, result, b64enc, err))) {
		if (!results->first_entry) {
			results->first_entry = lent;
		}
		if (!addtobucket(results->entries, lent)) {
			res = LDAP_NO_MEMORY;
			objunref(lent);
			break;
		}
		lent->next = NULL;
		if (prev) {
			prev->next = lent;
			lent->prev = prev;
		} else {
			lent->prev = NULL;
		}
		prev = lent;
		objunref(lent);
	}
	ldap_msgfree(result);

	if (err) {
		*err = res;
	}

	if (res) {
		objunref(results);
		results = NULL;
	}

	objunref(ld);
	return results;
}

extern struct ldap_results *ldap_search_sub(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...) {
	va_list a_list;
	char *attr, **tmp, **attrs = NULL;
	int cnt = 1;

	va_start(a_list, res);
	while (( attr=va_arg(a_list, void*))) {
		cnt++;
	}
	va_end(a_list);

	if (cnt > 1) {
		tmp = attrs = malloc(sizeof(void*)*cnt);

		va_start(a_list, res);
		while (( attr=va_arg(a_list, char*))) {
			*tmp = attr;
			tmp++;
		}
		va_end(a_list);
		*tmp=NULL;
	}

	return dts_ldapsearch(ld, base, LDAP_SCOPE_SUBTREE, filter, attrs, b64enc, res);
}

extern struct ldap_results *ldap_search_one(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...) {
	va_list a_list;
	char *attr, **tmp, **attrs = NULL;
	int cnt = 1;

	va_start(a_list, res);
	while (( attr=va_arg(a_list, void*))) {
		cnt++;
	}
	va_end(a_list);

	if (cnt > 1) {
		tmp = attrs = malloc(sizeof(void*)*cnt);

		va_start(a_list, res);
		while (( attr=va_arg(a_list, char*))) {
			*tmp = attr;
			tmp++;
		}
		va_end(a_list);
		*tmp=NULL;
	}

	return dts_ldapsearch(ld, base, LDAP_SCOPE_ONELEVEL, filter, attrs, b64enc, res);
}

extern struct ldap_results *ldap_search_base(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...) {
	va_list a_list;
	char *attr, **tmp, **attrs = NULL;
	int cnt = 1;

	va_start(a_list, res);
	while (( attr=va_arg(a_list, void*))) {
		cnt++;
	}
	va_end(a_list);

	if (cnt > 1) {
		tmp = attrs = malloc(sizeof(void*)*cnt);

		va_start(a_list, res);
		while (( attr=va_arg(a_list, char*))) {
			*tmp = attr;
			tmp++;
		}
		va_end(a_list);
		*tmp=NULL;
	}

	return dts_ldapsearch(ld, base, LDAP_SCOPE_BASE, filter, attrs, b64enc, res);
}

int ldap_count(LDAP *ld, LDAPMessage *message, int *err) {
	int x;

	objlock(ld);
	x = ldap_count_entries(ld, message);
	objunlock(ld);

	if (!err) {
		return x;
	}

	if (x < 0) {
		objlock(ld);
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, err);
		objunlock(ld);
	} else {
		*err = LDAP_SUCCESS;
	}
	return x;
}

char *ldap_getdn(LDAP *ld, LDAPMessage *message, int *err) {
	char *dn;

	objlock(ld);
	dn = ldap_get_dn(ld, message);
	objunlock(ld);
	
	if (!err) {
		return dn;
	}

	if (!dn) {
		objlock(ld);
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, err);
		objunlock(ld);
	} else {
		*err = LDAP_SUCCESS;
	}

	return dn;
}

char *ldap_getattribute(LDAP *ld, LDAPMessage *message, BerElement **berptr, int *err) {
	BerElement *ber = *berptr;
	char *attr = NULL;

	objlock(ld);
	if (ber) {
		attr = ldap_next_attribute(ld, message, ber);
	} else {
		attr = ldap_first_attribute(ld, message, berptr);
	}
	if (!err) {
		objunlock(ld);
		return attr;
	}

	if (!attr) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, err);
	} else {
		*err = LDAP_SUCCESS;
	}

	objunlock(ld);
	return attr;
}

char *ldap_encattr(void *attrval, int b64enc, enum ldap_attrtype *type) {
	struct berval *val = attrval;
	char *aval = NULL;
	int len, pos, atype;

	len = val->bv_len;
	for(pos=0; isprint(val->bv_val[pos]); pos++);
	if (pos == len) {
		aval = objalloc(val->bv_len+1, NULL);
		strncpy(aval, val->bv_val, objsize(aval));
		atype = LDAP_ATTRTYPE_CHAR;
	} else if (b64enc) {
		aval = b64enc_buf(val->bv_val, val->bv_len, 0);
		atype = LDAP_ATTRTYPE_B64;
	} else {
		aval = objalloc(val->bv_len, NULL);
		memcpy(aval, val->bv_val, objsize(aval));
		atype = LDAP_ATTRTYPE_OCTET;
	}

	if (type) {
		*type = atype;
	}

	return aval;
}

struct berval **ldap_attrvals(LDAP *ld, LDAPMessage *message, char *attr, int *cnt, int *err) {
	struct berval **vals = NULL;

	objlock(ld);
	vals = ldap_get_values_len(ld, message, attr);
	objunlock(ld);

	if (cnt) {
		*cnt = ldap_count_values_len(vals);
	}

	if (!err) {
		return vals;
	}

	if (!vals) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, err);
	} else {
		*err = LDAP_SUCCESS;
	}

	return vals;
}

int ldapattr_hash(const void *data, int key) {
        int ret;
        const struct ldap_attr *la = data;
        const char* hashkey = (key) ? data : la->name;

        if (hashkey) {
                ret = jenhash(hashkey, strlen(hashkey), 0);
        } else { 
                ret = jenhash(la, sizeof(la), 0);
        }
        return(ret);
}

struct bucket_list *attr2bl(LDAP *ld, LDAPMessage *message, struct ldap_attr **first, int b64enc, int *res) {
	BerElement *ber = NULL;
	struct bucket_list *bl;
	struct ldap_attr *la, *prev = NULL;
	struct ldap_attrval *lav, **lavals;
	struct berval **tmp, **vals = NULL;
	enum ldap_attrtype type;
	char *attr;
	int cnt;
	char *eval;

	if (!(bl = create_bucketlist(4, ldapattr_hash))) {
		if (res) {
			*res = LDAP_NO_MEMORY;
		}
		return NULL;
	}

	while((attr = ldap_getattribute(ld, message, &ber, res))) {
		tmp = vals = ldap_attrvals(ld, message, attr, &cnt, res);
		la = objalloc(sizeof(*la), free_attr);
		if (first && !*first) {
			*first = la;
		}
		la->next = NULL;
		if (prev) {
			prev->next = la;
			la->prev = prev;
		} else {
			la->prev = NULL;
		}
		prev = la;
		lavals = objalloc(sizeof(void*) * (cnt+1), free_attrvalarr);
		if (!lavals || !la) {
			if (res) {
				*res = LDAP_NO_MEMORY;
			}
			if (la) {
				objunref(la);
			}
			if (lavals) {
				objunref(lavals);
			}
			objunref(bl);
			ldap_value_free_len(vals);
			if (ber) {
				ber_free(ber, 0);
			}
			return NULL;
		}
		la->vals = lavals;
		la->name = attr;
		la->count = cnt;

		for(; *tmp; tmp++) {
			struct berval *bval = *tmp;

			*lavals = lav = objalloc(sizeof(*lav), free_attrval);
			lavals++;

			eval = ldap_encattr(bval, b64enc, &type);
			if (!eval || !lav) {
				if (res) {
					*res = LDAP_NO_MEMORY;
				}
				objunref(bl);
				objunref(la);
				if (eval) {
					objunref(eval);
				}
				ldap_value_free_len(vals);
				if (ber) {
					ber_free(ber, 0);
				}
				return NULL;
			}
			lav->len = bval->bv_len;
			lav->buffer = eval;
			lav->type = type;
		}
		*lavals = NULL;
		ldap_value_free_len(vals);
		addtobucket(bl, la);
		objunref(la);
	}
	if (ber) {
		ber_free(ber, 0);
	}
	return bl;
}

struct ldap_entry *ldap_getent(LDAP *ld, LDAPMessage **msgptr, LDAPMessage *result, int b64enc, int *err) {
	LDAPMessage *message = *msgptr;
	struct ldap_entry *ent = NULL;
	struct ldap_rdn *lrdn, *prev = NULL, *first = NULL;
	struct ldap_rdn **rdns;
	LDAPDN dnarr;
	LDAPRDN rdnarr;
	LDAPAVA *rdn;
	int res, cnt, tlen=0, dccnt=0;

	objlock(ld);
	if (message) {
		message = ldap_next_entry(ld, message);
	} else {
		message = ldap_first_entry(ld, result);
	}
	*msgptr = message;
	objunlock(ld);

	if (message && !(ent = objalloc(sizeof(*ent), free_entry))) {
		if (!err) {
			*err = LDAP_NO_MEMORY;
		}
		return NULL;
	} else if (!message) {
		if (err) {
			objlock(ld);
			ldap_get_option(ld, LDAP_OPT_RESULT_CODE, err);
			objunlock(ld);
		}
		return NULL;
	}

	if (!(ent->dn = ldap_getdn(ld, message, &res))) {
		if (err) {
			*err = res;
		}
		objunref(ent);
		return NULL;
	}

	objlock(ld);
	if ((res = ldap_str2dn(ent->dn, &dnarr, LDAP_DN_PEDANTIC))) {
		objunlock(ld);
		if (err) {
			*err = res;
		}
		objunref(ent);
		return NULL;		
	}
	objunlock(ld);

	ent->rdncnt = 0;
	for (cnt=0; dnarr[cnt]; cnt++) {
		rdnarr = dnarr[cnt];
		for (; *rdnarr; rdnarr++) {
			if (!(lrdn = objalloc(sizeof(*lrdn), free_rdn))) {
				for(lrdn = first;lrdn;lrdn=lrdn->next) {
					objunref(lrdn);
				}
				objunref(ent);
				if (err) {
					*err = LDAP_NO_MEMORY;
				}
				return NULL;
			}

			ent->rdncnt++;

			if (!first) {
				first = lrdn;
			}

			rdn = *rdnarr;
			ALLOC_CONST(lrdn->name, rdn->la_attr.bv_val);
			ALLOC_CONST(lrdn->value, rdn->la_value.bv_val); 

			if (!strcmp("dc", rdn->la_attr.bv_val)) {
				dccnt++;
			}
			tlen += rdn->la_value.bv_len;
			lrdn->next = NULL;
			if (prev) {
				prev->next = lrdn;
				lrdn->prev = prev;
			} else {
				lrdn->prev = NULL;
			}
			prev = lrdn;
		}
	}
	ldap_dnfree(dnarr);

	ent->dnufn = calloc(tlen + (ent->rdncnt-dccnt)*2+dccnt, 1);
	ent->rdn = rdns = objalloc(sizeof(void*) * (ent->rdncnt+1), free_rdnarr);

	if (!ent->dnufn || !ent->rdn) {
		for(lrdn = first;lrdn;lrdn=lrdn->next) {
			objunref(lrdn);
		}
		objunref(ent);
		if (err) {
			*err = LDAP_NO_MEMORY;
		}
	}

	for(lrdn = first;lrdn ;lrdn = lrdn->next) {
		strcat((char*)ent->dnufn, lrdn->value);
		if (lrdn->next && !strcmp(lrdn->name, "dc")) {
			strcat((char*)ent->dnufn, ".");
		} else if (lrdn->next) {
			strcat((char*)ent->dnufn, ", ");
		}
		*rdns = lrdn;
		rdns++;
	}
	*rdns = NULL;

	if (!(ent->attrs = attr2bl(ld, message, &ent->first_attr, b64enc, &res))) {
		if (err) {
			*err = res;
		}
		objunref(ent);
		return NULL;
	}

	if (err) {
		*err = LDAP_SUCCESS;
	}

	return ent;
}

extern void ldap_unref_attr(struct ldap_entry *entry, struct ldap_attr *attr) {
	if (!entry || !attr) {
		return;
	}

	if (objcnt(attr) > 1) {
		objunref(attr);
	} else {
		if (attr == entry->first_attr) {
			entry->first_attr = attr->next;
		}
		remove_bucket_item(entry->attrs, attr);
	}
}

extern void ldap_unref_entry(struct ldap_results *results, struct ldap_entry *entry) {
	if (!results || !entry) {
		return;
	}

	if (objcnt(entry) > 1) {
		objunref(entry);
	} else {
		if (entry == results->first_entry) {
			results->first_entry = entry->next;
		}
		remove_bucket_item(results->entries, entry);
	}
}

extern struct ldap_entry *ldap_getentry(struct ldap_results *results, const char *dn) {
	if (!results || !dn) {
		return NULL;
	}
	return (struct ldap_entry*)bucket_list_find_key(results->entries, dn);
}

extern struct ldap_attr *ldap_getattr(struct ldap_entry *entry, const char *attr) {
	if (!entry || !entry->attrs) {
		return NULL;
	}
	return (struct ldap_attr*)bucket_list_find_key(entry->attrs, attr);
}

extern struct ldap_modify *ldap_modifyinit(const char *dn) {
	struct ldap_modify *mod;
	int cnt;

	if (!(mod = objalloc(sizeof(*mod), free_modify))) {
		return NULL;
	}

	ALLOC_CONST(mod->dn, dn);
	if (!mod->dn) {
		objunref(mod);
		return NULL;
	}

	for(cnt=0; cnt < 3;cnt++) {
		if (!(mod->bl[cnt] = create_bucketlist(4, modify_hash))) {
			objunref(mod);
			return NULL;
		}
	}

	return mod;
}

struct ldap_modreq *new_modreq(struct bucket_list *modtype, const char *attr) {
	struct ldap_modreq *modr;

	if (!(modr = objalloc(sizeof(*modr), free_modreq))) {
		return NULL;
	}

	ALLOC_CONST(modr->attr, attr);
	if (!modr->attr || !addtobucket(modtype, modr)) {
		objunref(modr);
		modr = NULL;
	}
	return modr;
}

struct ldap_modreq *getmodreq(struct ldap_modify *lmod, const char *attr, int modop) {
	struct bucket_list *bl = NULL;
	struct ldap_modreq *modr = NULL;

	switch (modop) {
		case LDAP_MOD_REPLACE:
			bl = lmod->bl[0];
			break;
		case LDAP_MOD_DELETE:
			bl = lmod->bl[1];
			break;
		case LDAP_MOD_ADD:
			bl = lmod->bl[2];
			break;
	}

	if (bl && !(modr = bucket_list_find_key(bl, attr))) {
		if (!(modr = new_modreq(bl, attr))) {
			return NULL;
		}
	}
	return modr;
}

int add_modifyval(struct ldap_modreq *modr, const char *value) {
	struct ldap_modval *newval;

	if (!(newval = objalloc(sizeof(*newval), free_modval))) {
		return 1;
	}

	ALLOC_CONST(newval->value, value);
	if (!newval->value) {
		objunref(newval);
		return 1;
	}

	if (!modr->first) {
		modr->first = newval;
	}
	if (modr->last) {
		modr->last->next = newval;
	}
	modr->cnt++;
	modr->last = newval;

	return 0;
}

extern int ldap_mod_del(struct ldap_modify *lmod, const char *attr, ...) {
	va_list a_list;
	char *val;
	struct ldap_modreq *modr;

	if (!(modr = getmodreq(lmod, attr, LDAP_MOD_DELETE))) {
		return 1;
	}

	va_start(a_list, attr);
	while((val = va_arg(a_list, void*))) {
		if (add_modifyval(modr, val)) {
			objunref(modr);
			return(1);
		}
	}

	objunref(modr);
	va_end(a_list);
	return 0;
}

extern int ldap_mod_add(struct ldap_modify *lmod, const char *attr, ...) {
	va_list a_list;
	char *val;
	struct ldap_modreq *modr;

	if (!(modr = getmodreq(lmod, attr, LDAP_MOD_ADD))) {
		return 1;
	}

	va_start(a_list, attr);
	while((val = va_arg(a_list, void*))) {
		if (add_modifyval(modr, val)) {
			objunref(modr);
			return(1);
		}
	}

	objunref(modr);
	va_end(a_list);
	return 0;
}

extern int ldap_mod_rep(struct ldap_modify *lmod, const char *attr, ...) {
	va_list a_list;
	char *val;
	struct ldap_modreq *modr;

	if (!(modr = getmodreq(lmod, attr, LDAP_MOD_REPLACE))) {
		return 1;
	}

	va_start(a_list, attr);
	while((val = va_arg(a_list, void*))) {
		if (add_modifyval(modr, val)) {
			objunref(modr);
			return(1);
		}
	}

	objunref(modr);
	va_end(a_list);
	return 0;
}

LDAPMod *ldap_reqtoarr(struct ldap_modreq *modr, int type) {
	LDAPMod *modi;
	const char **mval;
	struct ldap_modval *modv;

	if (!(modi = calloc(sizeof(LDAPMod), 1))) {
		return NULL;
	}

	if (!(modi->mod_values = calloc(sizeof(void*), modr->cnt+1))) {
		free(modi);
		return NULL;
	}

	switch (type) {
		case 0: modi->mod_op = LDAP_MOD_REPLACE;
			break;
		case 1: modi->mod_op = LDAP_MOD_DELETE;
			break;
		case 2: modi->mod_op = LDAP_MOD_ADD;
			break;
		default: modi->mod_op = 0;
			break;
	}

	if (!(modi->mod_type = strdup(modr->attr))) {
		free(modi);
		return NULL;
	}

	mval = (const char**)modi->mod_values;
	for(modv = modr->first; modv; modv=modv->next) {
		if (!(*mval = strdup(modv->value))) {
			ldap_mods_free(&modi, 0);
			return NULL;
		}
		mval++;
	}
	*mval = NULL;

	return modi;
}

extern int ldap_domodify(struct ldap_conn *ld, struct ldap_modify *lmod) {
	struct bucket_loop *bloop;
	struct ldap_modreq *modr;
	LDAPMod **modarr, **tmp, *item;
	int cnt, tot=0, res;

	if (!objref(ld)) {
		return LDAP_UNAVAILABLE;
	}

	for(cnt = 0;cnt < 3;cnt++) {
		tot += bucket_list_cnt(lmod->bl[cnt]);
	}
	tmp = modarr = calloc(sizeof(void*), (tot+1));

	for(cnt = 0;cnt < 3;cnt++) {
		bloop = init_bucket_loop(lmod->bl[cnt]);
		while(bloop && ((modr = next_bucket_loop(bloop)))) {
			if (!(item = ldap_reqtoarr(modr, cnt))) {
				ldap_mods_free(modarr, 1);
				objunref(ld);
				return LDAP_NO_MEMORY;
			}
			*tmp = item;
			tmp++;
			objunref(modr);
		}
		stop_bucket_loop(bloop);
	}
	*tmp = NULL;

	objlock(ld);
	res = ldap_modify_ext_s(ld->ldap, lmod->dn, modarr, ld->sctrlsp, NULL);
	objunlock(ld);
	ldap_mods_free(modarr, 1);
	objunref(ld);
	return res;
}

extern int ldap_mod_delattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value) {
	struct ldap_modify *lmod;
	int res;

	if (!(lmod = ldap_modifyinit(dn))) {
		return LDAP_NO_MEMORY;
	}
	if (ldap_mod_del(lmod, attr, value, NULL)) {
		objunref(lmod);
		return LDAP_NO_MEMORY;		
	}

	res = ldap_domodify(ldap, lmod);
	objunref(lmod);
	return res;
}

extern int ldap_mod_remattr(struct ldap_conn *ldap, const char *dn, const char *attr) {
	return ldap_mod_delattr(ldap, dn, attr, NULL);
}

extern int ldap_mod_addattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value) {
	int res = 0;
	struct ldap_modify *lmod;

	if (!(lmod = ldap_modifyinit(dn))) {
		return LDAP_NO_MEMORY;
	}

	if (ldap_mod_add(lmod, attr, value, NULL)) {
		objunref(lmod);
		return LDAP_NO_MEMORY;	
	}

	res = ldap_domodify(ldap, lmod);
	objunref(lmod);
	return res;
}

extern int ldap_mod_repattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value) {
	struct ldap_modify *lmod;
	int res;

	if (!(lmod = ldap_modifyinit(dn))) {
		return LDAP_NO_MEMORY;
	}

	if (ldap_mod_rep(lmod, attr, value, NULL)) {
		objunref(lmod);
		return LDAP_NO_MEMORY;	
	}

	res = ldap_domodify(ldap, lmod);
	objunref(lmod);
	return res;
}

extern struct ldap_add *ldap_addinit(const char *dn) {
	struct ldap_add *mod;

	if (!(mod = objalloc(sizeof(*mod), free_add))) {
		return NULL;
	}

	ALLOC_CONST(mod->dn, dn);
	if (!mod->dn) {
		objunref(mod);
		return NULL;
	}

	if (!(mod->bl = create_bucketlist(4, modify_hash))) {
		objunref(mod);
		return NULL;
	}

	return mod;
}

struct ldap_modreq *getaddreq(struct ldap_add *ladd, const char *attr) {
	struct bucket_list *bl = ladd->bl;
	struct ldap_modreq *modr = NULL;

	if (bl && !(modr = bucket_list_find_key(bl, attr))) {
		if (!(modr = new_modreq(bl, attr))) {
			return NULL;
		}
	}
	return modr;
}

extern int ldap_add_attr(struct ldap_add *ladd, const char *attr, ...) {
	va_list a_list;
	char *val;
	struct ldap_modreq *modr;

	if (!(modr = getaddreq(ladd, attr))) {
		return 1;
	}

	va_start(a_list, attr);
	while((val = va_arg(a_list, void*))) {
		if (add_modifyval(modr, val)) {
			objunref(modr);
			return(1);
		}
	}

	objunref(modr);
	va_end(a_list);
	return 0;
}

extern int ldap_doadd(struct ldap_conn *ld, struct ldap_add *ladd) {
	struct bucket_loop *bloop;
	struct ldap_modreq *modr;
	LDAPMod **modarr, **tmp, *item;
	int tot=0, res;

	tot = bucket_list_cnt(ladd->bl);
	tmp = modarr = calloc(sizeof(void*), (tot+1));

	bloop = init_bucket_loop(ladd->bl);
	while(bloop && ((modr = next_bucket_loop(bloop)))) {
		if (!(item = ldap_reqtoarr(modr, -1))) {
			ldap_mods_free(modarr, 1);
			return LDAP_NO_MEMORY;
		}
		*tmp = item;
		tmp++;
		objunref(modr);
	}
	stop_bucket_loop(bloop);
	*tmp = NULL;

	objlock(ld);
	res = ldap_modify_ext_s(ld->ldap, ladd->dn, modarr, ld->sctrlsp, NULL);
	objunlock(ld);
	ldap_mods_free(modarr, 1);

	return res;
}
