#pragma once

/* Credit to OSS-FUZZ
 * https://github.com/google/oss-fuzz/blob/master/projects/nginx/fuzz/http_request_fuzzer.cc
 */

extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
}

#include <cstdio>
#include <string>
#include <fstream>

static ngx_cycle_t *cycle;
static ngx_log_t        ngx_log;
static ngx_open_file_t  ngx_log_file;

static ngx_http_request_t *req_reply;
static ngx_http_cleanup_t cln_new = {};
static int cln_added;

extern char **environ;

static char *fake_argv[2];
static char arg1[] = {0, 0xA, 0};

// Raw request & response data
static std::string request;
static std::string response;
void set_nginx_request(std::string req) { request = req; }
void set_nginx_response(std::string res) { response = res; }

static void cleanup_reply(void *data) { req_reply = NULL; }

//extern "C" void __gcov_dump();

// Handle sigint
void sigint_handler(int signum) {
    //__gcov_dump();
    exit(1);
}

static ssize_t request_recv_handler(ngx_connection_t *c, u_char *buf, size_t size) {
    if (request.size() < size) {
        size = request.size();
    }

    memcpy(buf, request.c_str(), size);
    request = request.substr(size);

    return size;
}

static ssize_t response_recv_handler(ngx_connection_t *c, u_char *buf, size_t size) {
    ngx_http_v2_connection_t *h2c = (ngx_http_v2_connection_t *)(c->data);

    if (h2c->state.stream != NULL) {
        req_reply = h2c->state.stream->request;

        if (!cln_added) {
            cln_added = 1;
            cln_new.handler = cleanup_reply;
            cln_new.next = req_reply->cleanup;
            cln_new.data = NULL;
            req_reply->cleanup = &cln_new;
        }
    }

    if (response.size() < size) {
        size = response.size();
    }

    memcpy(buf, response.c_str(), size);
    response = response.substr(size);

    if (size == 0) {
        c->read->ready = 0;
    }

    return size;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
    return NGX_OK;
}

static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
    return NGX_OK;
}

static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) {
    c->read->ready = 1;
    c->recv = response_recv_handler;
    return in->next;
}

// Create unique config file and socket for libfuzzer workers
static int create_unique_conf(char *filename_out)
{
    srand(getpid());

    char conf[8192];
    char conf_path[128], sock_path[128];

    for (;;) {
        int idx = rand();
        snprintf(conf_path, 128, "/tmp/nginx%d.conf", idx);
        snprintf(sock_path, 128, "/tmp/nginx%d.sock", idx);

        if (access(conf_path, F_OK) && access(sock_path, F_OK)) {
            snprintf(conf,
                    8192,
                    "error_log stderr emerg;\n"
                    "events {\n"
                    "   use epoll;\n"
                    "   worker_connections 2;\n"
                    "   multi_accept off;\n"
                    "   accept_mutex off;\n"
                    "}\n"
                    "http {\n"
                    "   error_log stderr emerg;\n"
                    "   access_log off;\n"
                    "   upstream fake_backend {\n"
                    "       server 127.0.0.1:1010 max_fails=0;\n"
                    "       server 127.0.0.1:1011 max_fails=0;\n"
                    "       server 127.0.0.1:1012 max_fails=0;\n"
                    "       server 127.0.0.1:1013 max_fails=0;\n"
                    "       server 127.0.0.1:1014 max_fails=0;\n"
                    "       server 127.0.0.1:1015 max_fails=0;\n"
                    "       server 127.0.0.1:1016 max_fails=0;\n"
                    "       server 127.0.0.1:1017 max_fails=0;\n"
                    "       server 127.0.0.1:1018 max_fails=0;\n"
                    "       server 127.0.0.1:1019 max_fails=0;\n"
                    "   }\n"
                    "   client_max_body_size 256M;\n"
                    "   client_body_temp_path /tmp/;\n"
                    "   proxy_temp_path /tmp/;\n"
                    "   proxy_buffer_size 24K;\n"
                    "   proxy_max_temp_file_size 0;\n"
                    "   proxy_buffers 8 4K;\n"
                    "   proxy_busy_buffers_size 28K;\n"
                    "   proxy_buffering off;\n"
                    "   server {\n"
                    "       listen unix:/tmp/nginx%d.sock http2;\n"
                    "       proxy_next_upstream off;\n"
                    "       proxy_read_timeout 5m;\n"
                    "       proxy_http_version 1.1;\n"
                    "       proxy_set_header Host $http_host;\n"
                    "       proxy_set_header X-Real-IP $remote_addr;\n"
                    "       proxy_set_header X-Real-Port $remote_port;\n"
                    "       location / {\n"
                    "           proxy_pass http://fake_backend;\n"
                    "           proxy_buffering off;\n"
                    "           proxy_cache off;\n"
                    "           chunked_transfer_encoding off;\n"
                    "       }\n"
                    "   }\n"
                    "}\n", idx);

            FILE *of = fopen(conf_path, "w");
            fwrite(conf, 1, strlen(conf), of);
            fclose(of);

            strncpy(filename_out, conf_path, 128);
            return 0;
        }
    }

    // Error
    return -1;
}


int setup_nginx()
{
    ngx_cycle_t init_cycle;
    ngx_log_t *log;

    ngx_debug_init();
    ngx_strerror_init();
    ngx_time_init();
    ngx_regex_init();

    // Just logging to stderr
    log = &ngx_log;
    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = NGX_LOG_EMERG;
    ngx_log_file.fd = ngx_stderr;

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    // Setup fake args
    fake_argv[0] = arg1;
    fake_argv[1] = NULL;
    ngx_argv = ngx_os_argv = fake_argv;
    ngx_argc = 0;

    // Weird trick to free a leaking buffer always caught by ASAN
    // We basically let ngx overwrite the environment variable, free the leak and
    // restore the environment as before.
    char *env_before = environ[0];
    environ[0] = ngx_argv[0] + 1;
    ngx_os_init(log);
    free(environ[0]);
    environ[0] = env_before;

    ngx_crc32_table_init();
    //ngx_slab_sizes_init();

    ngx_preinit_modules();

    // Create unique socket & config file for multiple libfuzzer workers
    char conf_file[128];
    if (create_unique_conf(conf_file) != 0) {
        fprintf(stderr, "create_unique_conf failed\n");
        return 1;
    }

    init_cycle.conf_file.len = strlen(conf_file);
    init_cycle.conf_file.data = (u_char *)conf_file;

    if ((cycle = ngx_init_cycle(&init_cycle)) == NULL) {
        fprintf(stderr, "ngx_init_cycle failed\n");
        return 1;
    }

    ngx_os_status(cycle->log);
    ngx_cycle = cycle;

    ngx_event_actions.add = add_event;
    ngx_event_actions.init = init_event;
    ngx_io.send_chain = send_chain;
    ngx_event_flags = 1;

    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);
    ngx_event_timer_init(cycle->log);

    // Lets also do this here
    signal(SIGINT, sigint_handler);
    return 0;
}

extern "C" long int invalid_call(ngx_connection_s *a, ngx_chain_s *b,
        long int c) {
    return 0;
}
