/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
 */

#ifndef FLB_OUT_COLLECTX
#define FLB_OUT_COLLECTX


#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

typedef int (*clx_callback_t)(const void *, const void *, size_t);

struct flb_collectx {
    void           *clx_provider_handle;
    clx_callback_t cb_write_events_to_clx;

    void           *collectx_provider_ctx;
    struct flb_output_instance *ins;  // pointer to the plugin info
                                      // ins->data can be used for user parameters
};


// TBD: REMOVE AFTER DEVELOPMENT
// /*
//  * Each initialized plugin must have an instance, same plugin may be
//  * loaded more than one time.
//  *
//  * An instance try to contain plugin data separating what is fixed data
//  * and the variable one that is generated when the plugin is invoked.
//  */
// struct flb_output_instance {
//     uint64_t mask_id;                    /* internal bitmask for routing */
//     int id;                              /* instance id                  */
//     int log_level;                       /* instance log level           */
//     char name[32];                       /* numbered name (cpu -> cpu.0) */
//     char *alias;                         /* alias name for the instance  */
//     int flags;                           /* inherit flags from plugin    */
//     int test_mode;                       /* running tests? (default:off) */
//     struct flb_output_plugin *p;         /* original plugin              */
//     void *context;                       /* plugin configuration context */

//     /* Plugin properties */
//     int retry_limit;                     /* max of retries allowed       */
//     int use_tls;                         /* bool, try to use TLS for I/O */
//     char *match;                         /* match rule for tag/routing   */
// #ifdef FLB_HAVE_REGEX
//     struct flb_regex *match_regex;       /* match rule (regex) based on Tags */
// #endif

// #ifdef FLB_HAVE_TLS
//     int tls_verify;                      /* Verify certs (default: true) */
//     int tls_debug;                       /* mbedtls debug level          */
//     char *tls_vhost;                     /* Virtual hostname for SNI     */
//     char *tls_ca_path;                   /* Path to certificates         */
//     char *tls_ca_file;                   /* CA root cert                 */
//     char *tls_crt_file;                  /* Certificate                  */
//     char *tls_key_file;                  /* Cert Key                     */
//     char *tls_key_passwd;                /* Cert Key Password            */
// #endif

//     /*
//      * network info:
//      *
//      * An input plugin can be specified just using it shortname or using the
//      * complete network address format, e.g:
//      *
//      *  $ fluent-bit -i cpu -o plugin://hostname:port/uri
//      *
//      * where:
//      *
//      *   plugin   = the output plugin shortname
//      *   name     = IP address or hostname of the target
//      *   port     = target TCP port
//      *   uri      = extra information that may be used by the plugin
//      */
//     struct flb_net_host host;

//     /*
//      * Optional data passed to the plugin, this info is useful when
//      * running Fluent Bit in library mode and the target plugin needs
//      * some specific data from it caller.
//      */
//     void *data;

//     /* Output handler configuration */
//     void *out_context;

//     /* IO upstream context, if flags & (FLB_OUTPUT_TCP | FLB_OUTPUT TLS)) */
//     struct flb_upstream *upstream;

//     /*
//      * The threads_queue is the head for the linked list that holds co-routines
//      * nodes information that needs to be processed.
//      */
//     struct mk_list th_queue;

// #ifdef FLB_HAVE_TLS
//     struct flb_tls tls;
// #else
//     void *tls;
// #endif

//     /*
//      * configuration properties: incoming properties set by the caller. This
//      * list is what the instance received by either a configuration file or
//      * through the command line arguments. This list is validated by the
//      * plugin.
//      */
//     struct mk_list properties;

//     /*
//      * configuration map: a new API is landing on Fluent Bit v1.4 that allows
//      * plugins to specify at registration time the allowed configuration
//      * properties and it data types. Config map is an optional API for now
//      * and some plugins will take advantage of it. When the API is used, the
//      * config map will validate the configuration, set default values
//      * and merge the 'properties' (above) into the map.
//      */
//     struct mk_list *config_map;

//     /* General network options like timeouts and keepalive */
//     struct flb_net_setup net_setup;
//     struct mk_list *net_config_map;
//     struct mk_list net_properties;

//     struct mk_list _head;                /* link to config->inputs       */

// #ifdef FLB_HAVE_METRICS
//     struct flb_metrics *metrics;         /* metrics                      */
// #endif

//     /* Callbacks context */
//     struct flb_callback *callback;

//     /* Tests */
//     struct flb_test_out_formatter test_formatter;

//     /*
//      * Buffer counter: it counts the total of disk space (filesystem) used by buffers
//      */
//     size_t fs_chunks_size;

//     /*
//      * Buffer limit: optional limit set by configuration so this output instance
//      * cannot buffer more than total_limit_size (bytes unit).
//      *
//      * Note that this is the limit set to the filesystem buffer mechanism so the
//      * input instance routered to this output plugin should configure to use
//      * filesystem as buffer type.
//      */
//     size_t total_limit_size;

//     /* Keep a reference to the original context this instance belongs to */
//     struct flb_config *config;
// };

// struct flb_output_thread {
//     int id;                            /* out-thread ID      */
//     const void *buffer;                /* output buffer      */
//     struct flb_task *task;             /* Parent flb_task    */
//     struct flb_config *config;         /* FLB context        */
//     struct flb_output_instance *o_ins; /* output instance    */
//     struct flb_thread *parent;         /* parent thread addr */
//     struct mk_list _head_output;       /* Link to flb_output_instance->th_queue */
//     struct mk_list _head;              /* Link to flb_task->threads */

// };




#endif  // FLB_OUT_COLLECTX
