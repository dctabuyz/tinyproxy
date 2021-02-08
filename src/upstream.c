/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
 * Copyright (C) 2009 Michael Adam <obnox@samba.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Routines for handling the list of upstream proxies.
 */

#include "upstream.h"
#include "heap.h"
#include "log.h"
#include "base64.h"
#include "basicauth.h"

#ifdef UPSTREAM_SUPPORT

const char *
proxy_type_name(proxy_type type)
{
    switch(type) {
        case PT_NONE: return "none";
        case PT_HTTP: return "http";
        case PT_SOCKS4: return "socks4";
        case PT_SOCKS5: return "socks5";
        default: return "unknown";
    }
}

/**
 * Construct an upstream struct from input data.
 */
struct upstream *upstream_build (const char *host, int port, const char *domain,
                                 const char *user, const char *pass,
                                 proxy_type type)
{
        char *ptr;
        struct upstream *up;

        up = (struct upstream *) safemalloc (sizeof (struct upstream));
        if (!up) {
                log_message (LOG_ERR,
                             "Unable to allocate memory in upstream_build()");
                return NULL;
        }

        up->type = type;
        up->host = up->domain = up->ua.user = up->pass = NULL;
        up->ip = up->mask = up->suspended_until = 0;
        if (user) {
                if (type == PT_HTTP) {
                        char b[BASE64ENC_BYTES((256+2)-1) + 1];
                        ssize_t ret;
                        ret = basicauth_string(user, pass, b, sizeof b);
                        if (ret == 0) {
                                log_message (LOG_ERR,
                                             "User / pass in upstream config too long");
                                return NULL;
                        }
                        up->ua.authstr = safestrdup (b);
                } else {
                        up->ua.user = safestrdup (user);
                        up->pass = safestrdup (pass);
                }
        }

        if (domain == NULL) {
                if (!host || host[0] == '\0' || port < 1) {
                        log_message (LOG_WARNING,
                                     "Nonsense upstream rule: invalid host or port");
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;

                log_message (LOG_INFO, "Added upstream %s %s:%d for [default]",
                             proxy_type_name(type), host, port);
        } else if (host == NULL || type == PT_NONE) {
                if (!domain || domain[0] == '\0') {
                        log_message (LOG_WARNING,
                                     "Nonsense no-upstream rule: empty domain");
                        goto fail;
                }

                ptr = strchr (domain, '/');
                if (ptr) {
                        struct in_addr addrstruct;

                        *ptr = '\0';
                        if (inet_aton (domain, &addrstruct) != 0) {
                                up->ip = ntohl (addrstruct.s_addr);
                                *ptr++ = '/';

                                if (strchr (ptr, '.')) {
                                        if (inet_aton (ptr, &addrstruct) != 0)
                                                up->mask =
                                                    ntohl (addrstruct.s_addr);
                                } else {
                                        up->mask =
                                            ~((1 << (32 - atoi (ptr))) - 1);
                                }
                        }
                } else {
                        up->domain = safestrdup (domain);
                }

                log_message (LOG_INFO, "Added no-upstream for %s", domain);
        } else {
                if (!host || host[0] == '\0' || port < 1 || !domain
                    || domain[0] == '\0') {
                        log_message (LOG_WARNING,
                                     "Nonsense upstream rule: invalid parameters");
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;
                up->domain = safestrdup (domain);

                log_message (LOG_INFO, "Added upstream %s %s:%d for %s",
                             proxy_type_name(type), host, port, domain);
        }

        return up;

fail:
        safefree (up->ua.user);
        safefree (up->pass);
        safefree (up->host);
        safefree (up->domain);
        safefree (up);

        return NULL;
}

/*
 * Add an entry to the upstream list
 */
void upstream_add (const char *host, int port, const char *domain,
                   const char *user, const char *pass, proxy_type type,
                   struct proxies **upstream_list)
{
        struct proxies *new;
        struct proxies *tmp = *upstream_list;

        struct upstream *pr = upstream_build (host, port, domain, user, pass, type);
        if (pr == NULL) {
                return;
        }

        /* TODO ip */

        while (tmp) {

                if ( tmp->domain && pr->domain && 0 == strcasecmp(tmp->domain, pr->domain) ) {
                        goto addproxy;
                }

                if ( tmp->next ) {
                        tmp = tmp->next;
                        continue;
                }

                if ( ! tmp->domain && ! pr->domain ) {
                        goto addproxy;
                }

                break;
        }

        new = (struct proxies *) safemalloc (sizeof (struct proxies));
        memset(new, 0, sizeof (struct proxies));
        new->next      = NULL;
        new->proxies_v = vector_create();

        if ( pr->domain ) {
                new->domain = safestrdup( pr->domain );
                new->next = *upstream_list;
        }
        else if ( tmp ) {
                tmp->next = new;
        }

        if ( ! *upstream_list ) {
                *upstream_list = new;
        }

        tmp = new;

addproxy:
        vector_append(tmp->proxies_v, pr, sizeof(*pr));
        /* free(pr->domain); */
        safefree(pr); /* NOTE vector_append() makes a copy */
}

/*
 * Check if a host is in the upstream list
 */
struct upstream *upstream_get (char *host, struct proxies *up)
{
        static unsigned int try_num   = 0;
        unsigned        int retry_num = 0;

        in_addr_t my_ip = INADDR_NONE;

        while (up) {

                if (up->domain) {
                        if (strcasecmp (host, up->domain) == 0)
                                break;  /* exact match */

                        if (up->domain[0] == '.') {
                                char *dot = strchr (host, '.');

                                if (!dot && !up->domain[1])
                                        break;  /* local host matches "." */

                                while (dot && strcasecmp (dot, up->domain))
                                        dot = strchr (dot + 1, '.');

                                if (dot)
                                        break;  /* subdomain match */
                        }
                } else if (up->ip) {
                        /* TODO */
                        if (my_ip == INADDR_NONE)
                                my_ip = ntohl (inet_addr (host));

                        if ((my_ip & up->mask) == up->ip)
                                break;
                } else {
                        break;  /* No domain or IP, default upstream */
                }

                up = up->next;
        }

        if ( up ) {

                ssize_t total_proxies = vector_length(up->proxies_v);

                while ( total_proxies > retry_num++ ) {

                        struct upstream *pr = (struct upstream *)up->proxies_a[ try_num++ % total_proxies ];

                        if ( 0 == pr->suspended_until || time(NULL) > pr->suspended_until ) {

                                log_message (LOG_INFO, "Found upstream proxy %s %s:%d for %s",
                                             proxy_type_name(pr->type), pr->host, pr->port, host);
                                return pr;
                        }

                        log_message (LOG_INFO, "Upstream proxy %s:%d is suspended, trying next...",
                                        pr->host,
                                        pr->port);
                };
        }

        log_message (LOG_INFO, "No upstream proxy for %s", host);
        return NULL;
}

void init_upstream_arrays(struct proxies **upstream_list) {
        struct proxies *tmp = *upstream_list;

        while ( tmp ) {

                ssize_t total_proxies = vector_length(tmp->proxies_v);
                ssize_t proxy_counter = 0;

                if ( total_proxies > 0 ) {
                        tmp->proxies_a = safemalloc(total_proxies * sizeof(struct upstream *));
                        if ( NULL == tmp->proxies_a ) {
                                /* TODO error message */
                                return;
                        }

                        while ( total_proxies > proxy_counter ) {
                                struct upstream *pr = (struct upstream *)vector_getentry(tmp->proxies_v, proxy_counter, NULL);
                                pr->proxy_count = total_proxies;
                                tmp->proxies_a[proxy_counter++] = pr;
                        }
                }

                tmp = tmp->next;
        }
}

void free_upstream_list (struct proxies *up)
{
        while (up) {
                struct proxies *tmp = up;
                ssize_t total_proxies = vector_length(tmp->proxies_v);
                up = tmp->next;
                while ( total_proxies-- > 0 ) {
                        safefree (tmp->proxies_a[total_proxies]->host);
                        if ( tmp->proxies_a[total_proxies]->domain )
                                safefree (tmp->proxies_a[total_proxies]->domain);
                        safefree (tmp->proxies_a[total_proxies]->ua.user);
                        safefree (tmp->proxies_a[total_proxies]->pass);
                }
                safefree (tmp->proxies_a);
                if ( tmp->domain )
                        safefree (tmp->domain);
                vector_delete(tmp->proxies_v);
                safefree (tmp);
        }
}

#endif
