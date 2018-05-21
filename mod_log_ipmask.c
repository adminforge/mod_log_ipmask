/*
 * -----------------------------------------------------------------------------
 * mod_log_ipmask - An Apache http server modul extending mod_log_config
 *                                      to masquerade Client IP-Addresses in logfiles
 *
 * Copyright (C) 2008 Mario Osswald,
 *                                        Referatsleiter "Technik, Informatik, Medien"
 *                                        beim
 *                                        Saechsischen Datenschutzbeauftragten
 *
 * Author                         Florian van Koten
 *                                        systematics NETWORK SERVICES GmbH
 *
 * ...with modifications (C) 2012 Peter Conrad
 * ...Peters IPv6 patch ported to work with apache2.4 (C) 2017 Ronny Seffner
 * -----------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 * -----------------------------------------------------------------------------
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"          /* Fuer REMOTE_NAME */
#include "mod_log_config.h"


#define DEFAULT_FILTER_BITS_V4 16
#define DEFAULT_FILTER_BITS_V6 32

static const char *V4_PFX = "\0\0\0\0\0\0\0\0\0\0\377\377";

struct apr_ipsubnet_t {
    int family;
#if APR_HAVE_IPV6
    apr_uint32_t sub[4]; /* big enough for IPv4 and IPv6 addresses */
    apr_uint32_t mask[4];
#else
    apr_uint32_t sub[1];
    apr_uint32_t mask[1];
#endif
};


/*
 * Modul-Deklaration
 */
module AP_MODULE_DECLARE_DATA log_ipmask_module;

static const int BUFLEN = 48;

static char* to_string(struct sockaddr *sa, size_t salen, apr_pool_t* pPool) {
        char *buf = apr_pcalloc(pPool, BUFLEN);
        int rv;
        if (!buf) { return NULL; }
        rv = getnameinfo(sa, salen, buf, BUFLEN, NULL, 0, NI_NUMERICHOST);
        if (rv) { *buf = 0; }
        return buf;
}

/**
* @brief        Maskiert eine IP-Adresse mit der angegebenen Filter-Maske.
*                       Die Filter-Maske entspricht
*                       der Anzahl der zu erhaltenen Bits (z.B. 24)
*                       Die Maske kann durch einen '/' getrennt verschiedene
*                       Werte fuer IPv4 und IPv6 enthalten.
*                       Die Filtermaske wird in der Logger-Konfiguration angegeben;
*                       Beispiel %{24}h oder %{24/56}a
* @param        char*           pszAddress (IP-Adresse)
* @param        char*           pszFilterMask (Filter-Maske)
* @param        apr_pool_t*     pPool
*/
static const char* get_filtered_ip(char* pszAddress, char* pszFilterMask, apr_pool_t* pPool) {
        char*                   pszFilteredIP = NULL;
        apr_status_t    rv;
        int bitsv4, bitsv6;
        struct addrinfo hints = {0}, *res = NULL;

        /* parse IP-Adress */
        hints.ai_flags = AI_NUMERICHOST | AI_V4MAPPED;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = 0;
        hints.ai_protocol = 0;
        rv = getaddrinfo(pszAddress, NULL, &hints, &res);

        if (!rv && res) {
                /* ok */
                if (*pszFilterMask == '\0') {
                        bitsv4 = DEFAULT_FILTER_BITS_V4;
                        bitsv6 = DEFAULT_FILTER_BITS_V6;
                } else {
                        char *slash = strchr(pszFilterMask, '/');
                        bitsv4 = atoi(pszFilterMask);
                        bitsv6 = slash ? atoi(slash + 1) : bitsv4;
                }
                if (bitsv4 > DEFAULT_FILTER_BITS_V4) { bitsv4 = DEFAULT_FILTER_BITS_V4; }
                if (bitsv6 > DEFAULT_FILTER_BITS_V6) { bitsv6 = DEFAULT_FILTER_BITS_V6; }
                if (res->ai_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *) res->ai_addr;
                        sin->sin_addr.s_addr &= htonl(0xffffffffU << (32-bitsv4));
                        pszFilteredIP = to_string((struct sockaddr *) sin, res->ai_addrlen, pPool);
                } else if (res->ai_family == AF_INET6) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
                        struct in6_addr *addr = &sin6->sin6_addr;
                        int i;
                        if (addr->s6_addr[0] == 0x20 && addr->s6_addr[1] == 0x02) {
                                bitsv6 = 16 + bitsv4;
                        } else if (!memcmp(addr->s6_addr, V4_PFX, 12)) {
                                bitsv6 = 96 + bitsv4;
                        }
                        for (i = 15; 8*i >= bitsv6; i--) {
                                addr->s6_addr[i] = 0;
                        }
                        if (bitsv6 & 7) {
                                addr->s6_addr[bitsv6 >> 3] &= 0xff << (8 - (bitsv6 & 7));
                        }
                        pszFilteredIP = to_string((struct sockaddr *) sin6, res->ai_addrlen, pPool);
                }
        }
        if (res) { freeaddrinfo(res); }

        return pszFilteredIP ? pszFilteredIP : pszAddress;
};


/**
 * @brief       Diese Funktion gibt die IP-Adresse des Clients maskiert zurueck, wenn
 *                      der Hostname nicht aufgeloest wurde
 *
 * @param       request_rec*    pRequest (request-Struktur)
 * @param       char*                   pszMask (Konfigurationsparameter fuer %h aus httpd.conf)
 */
static const char *log_remote_host_masked(request_rec* pRequest, char* pszMask)
{
        char* pszHost;

        pszHost = ap_escape_logitem(
                pRequest->pool,
                ap_get_remote_host(
                        pRequest->connection,
            pRequest->per_dir_config,
                        REMOTE_NAME,
                        NULL
        ));

        return get_filtered_ip(pszHost, pszMask, pRequest->pool);
}


/**
 * @brief       Diese Funktion gibt die IP-Adresse des Clients maskiert zurueck
 *
 * @param       request_rec*    pRequest (request-Struktur)
 * @param       char*                   pszMask (Konfigurationsparameter fuer %a aus httpd.conf)
 */
static const char *log_remote_address_masked(request_rec* pRequest, char* pszMask)
{
        char* pszAddress;

        if (!strcmp(pszMask, "c")) {
                // Apache 2.4: %{c}a ist die IP-Adresse der Connection, mglw. ein Proxy
                return pRequest->connection->client_ip;
        }

        pszAddress = pRequest->useragent_ip;

        return get_filtered_ip(pszAddress, pszMask, pRequest->pool);
}

/**
 * @brief       Diese Funktion ersetzt die LogFormat-Direktiven aus mod_log_config.c,
 *                      die Client IP-Adressen enthalten koennen, mit eigenen Handlern
 *
 * @param       apr_pool_t*     p
 * @param       apr_pool_t*     plog
 * @param       apr_pool_t*     ptemp
 */
static int ipmask_pre_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp)
{
        static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *ipmask_pfn_register;

        ipmask_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);
        if (ipmask_pfn_register) {
                ipmask_pfn_register(p, "h", log_remote_host_masked, 0);
                ipmask_pfn_register(p, "a", log_remote_address_masked, 0);
        }

        return OK;
}

/**
 * @brief       Diese Callback-Funktion registriert die pre-config-Funktion,
 *                      durch die die Handler fuer die LogFormat-Direktiven ersetzt
 *                      werden (%a und %h).
 *                      Diese pre-config-Funktion muss nach der aus mod_log_config.c
 *                      aufgerufen werden.
 *
 * @param       apr_pool_t*     p
 */
static void ipmask_register_hooks (apr_pool_t* p)
{
        static const char* const aszPre[] = {"mod_log_config.c", NULL};
        ap_hook_pre_config(ipmask_pre_config, aszPre, NULL, APR_HOOK_FIRST);
}

/*
 * Deklaration und Veroeffentlichung der Modul-Datenstruktur.
 * Der Name dieser Struktur ist wichtig ('log_ipmask_module') - er muss
 * mit dem Namen des Moduls uebereinstimmen, da diese Struktur die
 * einzige Verbindung zwischen dem http-Kern und diesem Modul ist.
 */
module AP_MODULE_DECLARE_DATA log_ipmask_module =
{
        STANDARD20_MODULE_STUFF,        /* standard stuff */
        NULL,                                           /* per-directory configuration structures */
        NULL,                                           /* merge per-directory */
        NULL,                                           /* per-server configuration structures */
        NULL,                                           /* merge per-server */
        NULL,                                           /* configuration directive handlers */
        ipmask_register_hooks,          /* Callback, um Hooks zu registrieren */
};
