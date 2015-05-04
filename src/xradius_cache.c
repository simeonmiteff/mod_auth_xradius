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

/**
 * Removes upto 128 Expired Sessions Per Call.
 * To Reset all Sessions, you can safely delete the DBM files used by the module.
 */
int xrad_cache_dbm_expire(server_rec *s, xrad_serverconf_rec* sc, 
                          apr_pool_t* p, apr_time_t current_time)
{
    apr_status_t rv;
    apr_dbm_t *dbm;
    apr_datum_t *keylist;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_time_t dtime;
    apr_pool_t* spool;
    int i = 0;
    int keyidx = 0;
    int should_delete = 0;
    
    /* A subpool to limit the memory usage. */
    apr_pool_create(&spool, p);

    /* The First pass just finds all of the DBM Entires that we can remove. */
    rv = apr_dbm_open(&dbm, sc->cache_config, APR_DBM_READONLY,
                      XRAD_DBM_FILE_MODE, spool);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     s,
                     "xradius: error opening cache searcher '%s'",
                     sc->cache_config);
        return -1;
    }
    
#define KEYMAX 128
    
    keylist = apr_palloc(spool, sizeof(dbmkey)*KEYMAX);
    
    apr_dbm_firstkey(dbm, &dbmkey);
    while (dbmkey.dptr != NULL) {
        apr_dbm_fetch(dbm, dbmkey, &dbmval);
        if (dbmval.dptr != NULL) {
            if (dbmval.dsize >= sizeof(apr_time_t)) {
                memcpy(&dtime, dbmval.dptr, sizeof(apr_time_t));
                if (dtime < current_time) {
                    should_delete = 1;
                }
            }
            else {
                /* The entry is too small to be valid. Delete it. */
                should_delete = 1;
            }
            
            if (should_delete == 1) {
                should_delete = 0;
                keylist[keyidx].dptr = apr_palloc(spool, dbmkey.dsize) ;
                memcpy(keylist[keyidx].dptr, dbmkey.dptr, dbmkey.dsize);
                keylist[keyidx].dsize = dbmkey.dsize;
                keyidx++;
                if (keyidx == KEYMAX) {
                    break;
                }
            }
            
        }
        apr_dbm_nextkey(dbm, &dbmkey);
    }
    apr_dbm_close(dbm);
    
    if (keyidx != 0) {
        /* Only Re-open the DBM File if we have entries to delete. */
        rv = apr_dbm_open(&dbm, sc->cache_config,
                          APR_DBM_RWCREATE,XRAD_DBM_FILE_MODE, spool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                         s, "xratidus: error opening cache writer '%s'",
                         sc->cache_config);
            return -1;
        }
        
        for (i = 0; i < keyidx; i++) {
            apr_dbm_delete(dbm, keylist[i]);
        }
        
        apr_dbm_close(dbm);
    }
    
    /* Release our temp usage. */
    apr_pool_destroy(spool);
    return 0;
}

/**
 * This is ran before Apache drops privileges, and hence it can
 * create new files.  Those new files need to be readable by the Apache User. 
 */
int xrad_cache_dbm_post_config(apr_pool_t *p, server_rec *s, 
                               xrad_serverconf_rec *sc)
{
    apr_status_t rv;
    apr_dbm_t* dbm;
    const char* path1;
    const char* path2;
    
    /* Create the Configured DBM Files if they do not exist. */
    rv = apr_dbm_open(&dbm, sc->cache_config, APR_DBM_RWCREATE, 
                      XRAD_DBM_FILE_MODE, p);
    
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "xradius: Cannot create DBM Cache at `%s'", 
                     sc->cache_config);
        return rv;
    }
    
    apr_dbm_close(dbm);
    
    /* If we are using Existing Files, clear out some expired sessions. */
    xrad_cache_dbm_expire(s, sc, p, apr_time_now());

    /* Find the Real Filenames used by the DBM */
    apr_dbm_get_usednames(p, sc->cache_config, &path1, &path2);
    /* The Following Code takes logic directly from mod_ssl's DBM Cache */ 
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    /* Running as Root */
    if (geteuid() == 0)  {
        /* Allow the configured Apache use to read/write to the DBM */
        chown(path1, unixd_config.user_id, -1);
        if (path2 != NULL) { 
            chown(path2, unixd_config.user_id, -1);
        }
    }
#endif
    
    return rv;
}

/**
 * See if this User/Hash Combination is present in the DBM Cache.
 * Returns DECLINED, if not found, HTTP status code otherwise.
 */
int xrad_cache_dbm_check(request_rec* r, xrad_serverconf_rec *sc,
                         const char* user, const char* password)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_status_t rv;
    const char* epass;
    const char* status;
    
    dbmkey.dptr  = apr_pstrcat(r->pool, "xradius:", ap_auth_name(r), ":", 
                               user, NULL);
    dbmkey.dsize = strlen(dbmkey.dptr) + 1;
    
    xrad_cache_dbm_expire(r->server, sc, r->pool, r->request_time);
    
    rv = apr_dbm_open(&dbm, sc->cache_config,
                      APR_DBM_READONLY, XRAD_DBM_FILE_MODE, r->pool);
    
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     r->server,
                     "xradius: error opening cache '%s'",
                     sc->cache_config);
        return DECLINED;
    }
    
    rv = apr_dbm_fetch(dbm, dbmkey, &dbmval);
    
    if (rv != APR_SUCCESS) {
        apr_dbm_close(dbm);
        return DECLINED;
    }
    
    apr_dbm_close(dbm);
    
    if (dbmval.dsize < (sizeof(apr_time_t)+sizeof(char)) || dbmval.dptr == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     r->server,
                     "xradius: val size: '%d'",
                     dbmval.dsize);        
        return DECLINED;
    }
    
    status = dbmval.dptr+sizeof(apr_time_t);
    epass = dbmval.dptr+sizeof(apr_time_t)+sizeof(char);
    
    ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                 r->server,
                 "xradius: fetched '%s':'%s'",
                 password, epass);
    
    if (status[0] == 'A') {
        if (strcmp(password, epass) == 0) {
            return OK;
        }
        else {
            return DECLINED;
        }
    }
    else {
        if (strcmp(password, epass) == 0) {
            return HTTP_UNAUTHORIZED;
        }
        else {
            return DECLINED;
        }
    }
    
    return HTTP_UNAUTHORIZED;
}

int xrad_cache_dbm_store(request_rec* r, xrad_serverconf_rec *sc,
                         const char* user, const char* password, int result)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_status_t rv;
    apr_time_t expiry;
    const char* estatus;
    
    dbmkey.dptr  = apr_pstrcat(r->pool, "xradius:", ap_auth_name(r), ":", 
                               user, NULL);
    dbmkey.dsize = strlen(dbmkey.dptr) + 1;
    
    /* create DBM value */
    dbmval.dsize = strlen(password) + 1 + sizeof(apr_time_t) + sizeof(char);
    dbmval.dptr  = (char *)malloc(dbmval.dsize);
    
    expiry = r->request_time + apr_time_from_sec(sc->cache_timeout);
    
    memcpy((char *)dbmval.dptr, &expiry, sizeof(apr_time_t));
    
    if (result == OK) {
        estatus = "A";
    }
    else {
        estatus = "D";
    }
    
    memcpy((char *)dbmval.dptr+sizeof(apr_time_t), estatus, sizeof(char));
    memcpy((char *)dbmval.dptr+sizeof(apr_time_t)+sizeof(char),
           password, strlen(password) + 1);
    
    rv = apr_dbm_open(&dbm, sc->cache_config,
                      APR_DBM_RWCREATE, XRAD_DBM_FILE_MODE, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     r->server,
                     "xradius: error opening cache '%s'",
                     sc->cache_config);
        free(dbmval.dptr);        
        return -1;
    }
    
    rv = apr_dbm_store(dbm, dbmkey, dbmval);
    
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     r->server,
                     "xradius: error storing in cache '%s'",
                     sc->cache_config);
        apr_dbm_close(dbm);
        free(dbmval.dptr);
        return -1;
    }
    
    apr_dbm_close(dbm);
    
    free(dbmval.dptr);
    
    return 0;    
}


#if HAVE_APR_MEMCACHE

/* The underlying apr_memcache system is thread safe. */
static apr_memcache_t* mc;

int xrad_cache_mc_child_init(apr_pool_t *p, server_rec *s, 
                             xrad_serverconf_rec *sc)
{
    apr_status_t rv = APR_SUCCESS;
    int thread_limit = 0;
    int nservers = 0;
    char* cache_config;
    char* split;
    char* tok;
    
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    
    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, sc->cache_config);
    split = apr_strtok(cache_config, " ", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL," ", &tok);
    }
    
    rv = apr_memcache_create(p, nservers, 0, &mc);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "xradius: Failed to create Memcache Object of '%d' size.", 
                     nservers);
        return rv;
    }
    
    /* Now add each server to the memcache */
    cache_config = apr_pstrdup(p, sc->cache_config);
    split = apr_strtok(cache_config, " ", &tok);
    while (split) {
        apr_memcache_server_t* st;
        char* host_str;
        char* scope_id;
        apr_port_t port;
        
        rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "xradius: Failed to Parse Cache Server: '%s'", split);
            return rv;
        }
        
        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "xradius: Failed to Parse Cache Server, "
                         "no hostname specified: '%s'", split);
            return rv;
        }
        
        if (port == 0) {
            port = 11211; /* default port */
        }
        
        /* Should Max Conns be (thread_limit / nservers) ? */
        rv = apr_memcache_server_create(p,
                                        host_str, port,
                                        0, 1,
                                        thread_limit, 600, &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "xradius: Failed to Create Cache Server: %s:%d", 
                         host_str, port);
            return rv;
        }
        
        rv = apr_memcache_add_server(mc, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "xradius: Failed to Add Cache Server: %s:%d", 
                         host_str, port);
            return rv;
        }
        
        split = apr_strtok(NULL," ", &tok);
    }
    return rv;
}

/**
 * See if this User/Hash Combination is present in the Memcached Cache.
 * Returns DECLINED, if not found, HTTP status code otherwise.
 */
int xrad_cache_mc_check(request_rec* r, xrad_serverconf_rec *sc,
                        const char* user, const char* password)
{
    apr_status_t rv = APR_SUCCESS;
    apr_uint16_t flags;
    char* strkey = NULL;
    char* value;
    apr_size_t value_len;
    
    strkey = apr_pstrcat(r->pool, "xradius:", ap_auth_name(r), ":", 
                         user, NULL);
    
    /* memcache keys cannot contain a space. */
    strkey = ap_escape_uri(r->pool, strkey);
    
    rv = apr_memcache_getp(mc, r->pool, strkey,
                           &value, &value_len, &flags);
 
    if (rv == APR_NOTFOUND) {
        return DECLINED;
    }
    else if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                     r->server,
                     "xradius: memcache error fetching key '%s' ",
                     strkey);
        return DECLINED;
    }

    if (flags == 1) {
        if (strcmp(value, password) == 0) {
            return OK;
        }
        else {
            return DECLINED;
        }
    }
    else {
        /* If they match the negative cache, deny. */
        if (strcmp(value, password) == 0) {
#if XRAD_DEBUG
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                         r->server,
                         "xradius: negative cache hit: %s",
                         strkey);            
#endif
            return HTTP_UNAUTHORIZED;
        }
        else {
#if XRAD_DEBUG
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                         r->server,
                         "xradius: negative cache miss: %s",
                         strkey);
#endif
            return DECLINED;
        }
    }
    
    return HTTP_UNAUTHORIZED;
}

int xrad_cache_mc_store(request_rec* r, xrad_serverconf_rec *sc,
                         const char* user, const char* password, int result)
{
    apr_status_t rv = APR_SUCCESS;
    char* strkey = NULL;
    apr_uint16_t flags;
    
    strkey = apr_pstrcat(r->pool, "xradius:", ap_auth_name(r), ":", 
                         user, NULL);
    /* memcache keys cannot contain a space. */
    strkey = ap_escape_uri(r->pool, strkey);
    
    if (result == OK) {
        flags = 1;
    }
    else {
        flags = 0;
    }
    
    rv = apr_memcache_set(mc, strkey, (char*)password, strlen(password), 
                          sc->cache_timeout, flags);
    
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                     r->server,
                     "xradius: memcacche error setting key '%s'",
                     strkey);
        return -1;
    }
    
    return 0;    
}

#endif

