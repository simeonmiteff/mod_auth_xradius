/**
 *  Copyright 2005, Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "mod_auth_xradius.h"

#include "apr_md5.h"
#include "util_md5.h"

#if USING_2_1_RECENT
#include "ap_provider.h"
#include "mod_auth.h"
#endif

/* All use of the RADIUS Library is contained to this file. */
#include "radlib.h"

/* Macros used to simplify the setting of variables in the RADIUS Request */
#define _xrad_put_string(rvx, ctx, key, value)   \
rvx = xrad_put_string(ctx, key, value); \
if (rvx != 0) { \
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, \
                  "xradius: Failed to put "#key": (%d) %s", \
                  rvx, xrad_strerror(rctx)); \
                      goto run_cleanup; \
}

#define _xrad_put_int(rvx, ctx, key, value)   \
rvx = xrad_put_int(ctx, key, value); \
if (rvx != 0) { \
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, \
                  "xradius: Failed to put "#key": (%d) %s", \
                  rvx, xrad_strerror(rctx)); \
                      goto run_cleanup; \
}

apr_proc_mutex_t *gmutex;
static int use_mutex;

/**
 * This function does the actual validation of the submitted username and 
 * password.  The values in the username and password have already been vetted
 * for bogus values / large values by the httpd core.
 */
static int xrad_run_auth_check(request_rec* r, const char* user,
                               const char* password)
{
    int i;
    int rc; 
    int can_cache = 0;
    int ret = HTTP_UNAUTHORIZED; 
    struct xrad_handle* rctx = NULL;
    xrad_server_info *sr; 
    apr_md5_ctx_t md5ctx;
    char* digest = NULL;
    
    xrad_dirconf_rec *dc = ap_get_module_config(r->per_dir_config,
                                                &auth_xradius_module);

    xrad_serverconf_rec *sc = ap_get_module_config(r->server->module_config,
                                                &auth_xradius_module);

    /**
     * If no RADIUS servers have been configured, we always deny access.
     */
    if (dc->servers == NULL || apr_is_empty_array(dc->servers)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "xradius: no servers configured for authentication!");
        return HTTP_UNAUTHORIZED;
    }
    
    if (dc->reject_blank && strlen(password) == 0) {
        return HTTP_UNAUTHORIZED;
    }
    
    /*
     */
    if (use_mutex) {
        apr_proc_mutex_unlock(gmutex);
    }
    
    /**
     * Step 1: Check the Positive and Negative Cache Backends.
     *         Only one cache type can be active at a time.
     */
    if (sc->cache_type != xrad_cache_none) {
        apr_md5_init(&md5ctx);
        apr_md5_update(&md5ctx, password, strlen(password));
        digest = ap_md5contextTo64(r->pool, &md5ctx);
        
        if (sc->cache_type == xrad_cache_dbm) {
            rc = xrad_cache_dbm_check(r, sc, user, digest);
            if (rc != DECLINED) {
                ret = rc;
                goto run_cleanup;
            }
        }
#if HAVE_APR_MEMCACHE
        else if (sc->cache_type == xrad_cache_memcache) {
            rc = xrad_cache_mc_check(r, sc, user, digest);
            if (rc != DECLINED) {
                ret = rc;
                goto run_cleanup;
            }
        }
#endif
    }    
    /**
     * Step 2: The User/Password combination wasn't found in the database,
     *          So we are going to use RADIUS for this request.
     */
    rctx = xrad_auth_open();

    /* Loop through the array of RADIUS Servers, adding them to the rctx object */
    sr = (xrad_server_info *) dc->servers->elts;
    for (i = 0; i < dc->servers->nelts; ++i) {        
        rc = xrad_add_server(rctx, sr[i].hostname, sr[i].port, sr[i].secret,
                             dc->timeout, dc->maxtries);
        
        if (rc != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "xradius: Failed to add server '%s:%d': (%d) %s",
                          sr[i].hostname, sr[i].port, rc, xrad_strerror(rctx));
            goto run_cleanup;
        }        
    }
    
    /** 
     * Variables set for the RADIUS Authentication Request:
     *      request type:   RAD_ACCESS_REQUEST;
     *      service type:   RAD_SERVICE_TYPE     : RAD_AUTHENTICATE_ONLY
     *      nas host:       RAD_NAS_IDENTIFIER   : r->hostname
     *      nas Port:       RAD_NAS_PORT_TYPE    : RAD_VIRTUAL
     *      username:       RAD_USER_NAME        : user
     *      password:       RAD_PASSWORD         : password
     */

    /* Step 2.1: Create the Access Request */
    rc = xrad_create_request(rctx, RAD_ACCESS_REQUEST);
    if (rc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "xradius: Failed to create request: (%d) %s",
                      rc, xrad_strerror(rctx));
        goto run_cleanup;
    }
    
    /* Step 2.2: Put the Variables into the Request */
    _xrad_put_int(rc, rctx, RAD_SERVICE_TYPE, RAD_AUTHENTICATE_ONLY);
    _xrad_put_int(rc, rctx, RAD_NAS_PORT_TYPE, RAD_VIRTUAL);
    _xrad_put_string(rc, rctx, RAD_USER_NAME, user);
    _xrad_put_string(rc, rctx, RAD_NAS_IDENTIFIER, r->hostname);
    _xrad_put_string(rc, rctx, RAD_USER_PASSWORD, password);

    /* Step 2.3: Send the Request to the server(s). This is a blocking Operation.*/
    rc = xrad_send_request(rctx);

    /* Step 2.4: Check What the RADIUS Server said. */
    if (rc == RAD_ACCESS_ACCEPT) {
        /* An Accepted Client, make sure this result is cached. */
#if XRAD_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "xradius: '%s' -> RAD_ACCESS_ACCEPT",
                      user);
#endif
        can_cache = 1;
        ret = OK;
    }
    else if (rc == RAD_ACCESS_REJECT) {
        /* An Rejected Client. Commonly for the wrong password. */
#if XRAD_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "xradius: user '%s' was rejected by the server.",
                      user);
#endif
        ret = HTTP_UNAUTHORIZED;
        can_cache = 1;
        ap_note_basic_auth_failure(r);
    }
    else if (rc == RAD_ACCESS_CHALLENGE) {
        /**
         * libradius does not ever return 'RAD_ACCESS_CHALLENGE', 
         * But, it is documented as a possible return value.  We handle it here, 
         * in the case it is ever implemented.
         */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "xradius: user '%s' retutned CHALLENGE. Fatal Error.",
                      user);
        ret = HTTP_UNAUTHORIZED;
        ap_note_basic_auth_failure(r);
    }
    else {
        /**
         * This is the catch all.  Most common cause is we could not contact
         * the RADIUS server.  Default to DENY Access.
         */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "xradius: RADIUS Request for user '%s' failed: (%d) %s",
                      user, rc, xrad_strerror(rctx));
        ret = HTTP_UNAUTHORIZED;
        ap_note_basic_auth_failure(r);
    }
    
    /* Step 3: Store Result into the Cache. */
    if (can_cache) {
        if (sc->cache_type == xrad_cache_dbm) {
            rc = xrad_cache_dbm_store(r, sc, user, digest, ret);
        }
#if HAVE_APR_MEMCACHE
        else if (sc->cache_type == xrad_cache_memcache) {
            rc = xrad_cache_mc_store(r, sc, user, digest, ret);
        }
#endif
    }
    
run_cleanup:
    if (rctx) {
        /* Cleanup the Resources used by libradius */
        xrad_close(rctx);
    }
    
    if (use_mutex) {
        apr_proc_mutex_lock(gmutex);
    }
    
    return ret;    
}

#if USING_2_1_RECENT

static authn_status xrad_check_pw(request_rec * r, const char *user,
                                 const char *password)
{
    authn_status arv;
    int rv;
    
    rv = xrad_run_auth_check(r, user, password);
    
    if (rv == OK) {
        arv = AUTH_GRANTED;
    }
    else {
        /* Default to deny */
        arv = AUTH_DENIED;
    }
    
    /* TODO: Support AUTH_GENERAL_ERROR and AUTH_USER_NOT_FOUND */
    return arv;
}

#else /* Using 2.0.xx */
/* The Entry Point from Apache, for validating the User ID/Passsword */
static int xrad_check_user_id(request_rec *r)
{
    const char *sent_pw;
    int rv;

    /**
     * Fetch the password from the HTTP Headers.  If it was not supplied, this 
     * will return !OK, and prompt the client for their user/password 
     */
    rv = ap_get_basic_auth_pw(r, &sent_pw);
    if (rv != OK) {
        return rv;
    }
    
    /* The User did Submit a Username and Password, do the Authentication Check now. */
    return xrad_run_auth_check(r, r->user, sent_pw);
}

#endif

/* Adds a RADIUS Server to the Directory Configuration */
static const char *xrad_conf_add_server(cmd_parms * parms, void *dummy,
                                        const char *server_addr, const char* secret)
{
    xrad_dirconf_rec *dc = dummy;
    apr_status_t rv;
    char* scope_id;
    xrad_server_info *sr; 
    
    /* To properly use the Pools, this array is allocated from the here, instead of
        inside the directory configuration creation function. */
    if (dc->servers == NULL) {
        dc->servers = apr_array_make(parms->pool, 4, sizeof(xrad_server_info*));
    }
    
    sr = apr_array_push(dc->servers);

    /**
     * format like "radius.example.com:1183". This also understands IP Addresses
     * and IPv6 Addresses.
     */
    rv = apr_parse_addr_port(&sr->hostname, &scope_id, &sr->port, server_addr, 
                             parms->pool);
    
    if (rv != APR_SUCCESS) {
        /* We didn't use this space in the array. pop it off */
        apr_array_pop(dc->servers);
        return "AuthXRadiusAddServer: Invalid 'server' string.";
    }
    
    if (sr->hostname == NULL) {
        apr_array_pop(dc->servers);
        return "AuthXRadiusAddServer: Invalid server string. No hostname found";
    }

    if (sr->port == 0) {
        sr->port = RAD_DEFAULT_PORT;
    }
    
    sr->secret = apr_pstrdup(parms->pool, secret);
    /* no error in the parameters */
    return NULL;
}

/* Sets the global cache timeout. */
static const char *xrad_conf_cache_timeout(cmd_parms * parms, void *dummy,
                                           const char *time)
{
    const char* err;

    xrad_serverconf_rec *sc = ap_get_module_config(parms->server->module_config,
                                                   &auth_xradius_module);

    /* The Cache Configuration Must take place in the global context only. */
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }

    sc->cache_timeout = atoi(time);
    return NULL;
}    

/* Sets the global cache timeout. */
static const char *xrad_conf_cache_mutex(cmd_parms * parms, void *dummy,
                                           const char *arg)
{
    const char* err;
    
    /* The Cache Configuration Must take place in the global context only. */
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }
    
    if (strcasecmp("on", arg) == 0) {
        use_mutex = 1;
    }
    else if (strcasecmp("off", arg) == 0) {
        use_mutex = 0;
    }
    else {
        return "AuthXRadiusCacheMutex: Argument must be 'on' or 'off'.";
    }
    
    return NULL;
}    

/* Sets the Cache type, and the Cache Args */
static const char *xrad_conf_cache_conifg(cmd_parms * parms, void *dummy,
                                          const char *type, const char* arg)
{
    const char* err;
    xrad_serverconf_rec *sc = ap_get_module_config(parms->server->module_config,
                                                   &auth_xradius_module);

    /* The Cache Configuration Must take place in the global context only. */
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }
    
    if (strcasecmp("none", type) == 0) {
        sc->cache_type = xrad_cache_none;
    }
    else if (strcasecmp("dbm", type) == 0) {
        sc->cache_type = xrad_cache_dbm;
    }
#if HAVE_APR_MEMCACHE
    else if (strcasecmp("memcache", type) == 0) {
        sc->cache_type = xrad_cache_memcache;
    }
#endif
    else {
        return "Invalid Type for AuthXRadiusCache!";
    }
    
    if (sc->cache_type == xrad_cache_dbm) {
        /* The DBM Cache uses a possibly Relative File Path */
        sc->cache_config = ap_server_root_relative(parms->pool, arg);
    }
    else {
        sc->cache_config = apr_pstrdup(parms->pool, arg);
    }
    
    return NULL;
}

/* Allocate the Directory Configuration, and set default values. */
void *xrad_create_dirconf(apr_pool_t *p, char *dir)
{
    xrad_dirconf_rec *dc = apr_palloc(p, sizeof(*dc));

    dc->reject_blank = 1;
    dc->timeout = RAD_DEFAULT_TIMEOUT;
    dc->maxtries = RAD_DEFAULT_MAX_TRIES;
    dc->servers = NULL;
    return dc;
}

/* Allocate the Server Configuration, and set default values. */
static void *xrad_create_serverconf(apr_pool_t * p, server_rec * s)
{
    xrad_serverconf_rec *sc = apr_pcalloc(p, sizeof(*sc));
    
    sc->cache_type = xrad_cache_none;
    sc->cache_config = NULL;
    sc->cache_timeout = RAD_DEFAULT_CACHE_TIMEOUT;
    return sc;
}

/**
 * Since the Global Auth Cache should only be set globally, 
 * this propogates the global settings down to all children servers
 */
void *xrad_merge_serverconf(apr_pool_t *p, void *basev, void *addv)
{
    xrad_serverconf_rec *base = (xrad_serverconf_rec *)basev;
    xrad_serverconf_rec *mrg  = apr_pcalloc(p, sizeof(*mrg));
    
    mrg->cache_type = base->cache_type;
    mrg->cache_config = base->cache_config ? apr_pstrdup(p, base->cache_config) : NULL;
    mrg->cache_timeout = base->cache_timeout;

    return mrg;
}


/* This is called by Apache every tiem after the configuration is read. */
static int xrad_post_config(apr_pool_t* p, apr_pool_t* plog,
                            apr_pool_t* ptemp,
                            server_rec* s)
{
    apr_status_t rv;
    void *data = NULL;
    int first_run = 0;
    const char* userdata_key = "mod_auth_xradius_init";
    xrad_serverconf_rec* sc;
    
    /**
     * The First run of the configuration is rather useless.
     * After running, everything is cleared.  This is used for testing, 
     * and making sure everything can be parsed.
     */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (data == NULL) {
        first_run = 1;
        apr_pool_userdata_set((const void *)1, userdata_key, 
                              apr_pool_cleanup_null, 
                              s->process->pool);
    }
    
    if (!first_run) {
        sc = (xrad_serverconf_rec *) ap_get_module_config(s->module_config,
                                                          &auth_xradius_module);
        if (use_mutex) {
            rv = apr_proc_mutex_create(&gmutex, NULL, 
                                   APR_LOCK_DEFAULT, s->process->pool);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "xradius: Cannot create Cache Process Lock: (%d)", 
                         rv);
                return rv;
            }
        }
        if (sc->cache_type == xrad_cache_dbm) {
            /**
             * The DBM Cache requires some extra steps before the children fork
             * and drop priviledges. 
             */
            return xrad_cache_dbm_post_config(ptemp, s, sc);
        }
    }
    
    return OK;
}


static void xrad_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;
    xrad_serverconf_rec *sc = ap_get_module_config(s->module_config,
                                                   &auth_xradius_module);
    if (use_mutex) {
        rv = apr_proc_mutex_child_init(&gmutex, NULL, s->process->pool);
    
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "xradius: Cannot connect to Cache Process Lock in child: (%d)", 
                         rv);
        }
    }
    
    if (sc->cache_type == xrad_cache_dbm) {
        /* noop */
    }
#if HAVE_APR_MEMCACHE
    else if (sc->cache_type == xrad_cache_memcache) { 
        /* This Creates the memcache object inside every child process. */
        xrad_cache_mc_child_init(p, s, sc);
    }
#endif
}

#if USING_2_1_RECENT
static const authn_provider authn_xradius_provider = {
    &xrad_check_pw,
    NULL
};
#endif

/* Tell Apache Which Parts we want to Control Ourselves. */
static void xrad_hooks(apr_pool_t * p)
{
    use_mutex = 0;
    
    ap_hook_post_config(xrad_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(xrad_child_init, NULL, NULL, APR_HOOK_MIDDLE);   
#if USING_2_1_RECENT
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "xradius", "0",
                         &authn_xradius_provider);
#else
    ap_hook_check_user_id(xrad_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}

/* Our Configuration Commands */
static const command_rec xrad_cmds[] = {
    AP_INIT_TAKE2("AuthXRadiusCache", xrad_conf_cache_conifg,
                  NULL,
                  RSRC_CONF,
                  "Configure the Caching System"),    
    AP_INIT_TAKE1("AuthXRadiusCacheTimeout", xrad_conf_cache_timeout,
                  NULL,
                  RSRC_CONF,
                  "Set the Timeout for the Cache"),
    AP_INIT_TAKE1("AuthXRadiusCacheMutex", xrad_conf_cache_mutex,
                  NULL,
                  RSRC_CONF,
                  "Set the Timeout for the Cache"),
    AP_INIT_TAKE2("AuthXRadiusAddServer", xrad_conf_add_server,
                  NULL,
                  OR_AUTHCFG,
                  "Add a RADIUS Server to try for Authentication"),     
    AP_INIT_TAKE1("AuthXRadiusTimeout", ap_set_int_slot,
                  (void*)APR_OFFSETOF(xrad_dirconf_rec, timeout),
                  OR_AUTHCFG,
                  "Set the Timeout for Connecting to a RADIUS Server."), 
    AP_INIT_TAKE1("AuthXRadiusRetries", ap_set_int_slot,
                  (void*)APR_OFFSETOF(xrad_dirconf_rec, maxtries),
                  OR_AUTHCFG,
                  "Set the Number of Retries for connecting to a RADIUS Server."), 
    AP_INIT_FLAG("AuthXRadiusRejectBlank", ap_set_flag_slot,
                  (void*)APR_OFFSETOF(xrad_dirconf_rec, reject_blank),
                  OR_AUTHCFG,
                  "Reject all Blank Passwords from users."),    
    {NULL}
};

/* The Module Definition */
module AP_MODULE_DECLARE_DATA auth_xradius_module = {
    STANDARD20_MODULE_STUFF,
    xrad_create_dirconf,
    NULL,
    xrad_create_serverconf,
    xrad_merge_serverconf,
    xrad_cmds,
    xrad_hooks
};
