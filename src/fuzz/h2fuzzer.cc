extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <signal.h>
}

#include <cstdio>

#include "nginx_harness.h"
#include "h2_sequence.pb.h"
#include "h2_frame_grammar.pb.h"
#include "protobuf_encoders.h"
#include "hpack_compressor.h"
#include "src/libfuzzer/libfuzzer_macro.h"


DEFINE_PROTO_FUZZER(const h2proto::Conversation &input)
{
    static int init = setup_nginx();
    assert(init == 0);

    auto request = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    std::string response;

    for (auto ex : input.exchanges()) {
        request += Encode(ex.request_sequence());
        response += Encode(ex.request_sequence());
    }

    set_nginx_request(request);
    set_nginx_response(response);

    // Create event and connection
    ngx_event_t client_rev = {};
    ngx_event_t client_wev = {};
    ngx_connection_t client_local = {
        .read = &client_rev,
        .write = &client_wev,
    };

    ngx_event_t server_rev = {};
    ngx_event_t server_wev = {};
    ngx_connection_t server_local = {
        .read = &server_rev,
        .write = &server_wev,
        .send_chain = send_chain
    };

    req_reply = NULL;
    cln_added = 0;

    ngx_cycle->free_connections = &client_local;
    client_local.data = &server_local;
    ngx_cycle->free_connection_n = 2;

    ngx_listening_t *ls = (ngx_listening_t *)ngx_cycle->listening.elts;

    // Setup nginx connection
    ngx_connection_t *c = ngx_get_connection(255, &ngx_log);
    c->shared = 1;
    c->destroyed = 0;
    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(256, ngx_cycle->log);
    c->sockaddr = ls->sockaddr;
    c->listening = ls;
    c->recv = request_recv_handler;//(ngx_recv_pt)invalid_call;
    c->send_chain = send_chain;
    c->send = (ngx_send_pt)invalid_call;
    c->recv_chain = (ngx_recv_chain_pt)invalid_call;
    c->log = &ngx_log;
    c->pool->log = &ngx_log;
    c->read->log = &ngx_log;
    c->write->log = &ngx_log;
    c->socklen = ls->socklen;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;
    c->data = NULL;

    client_rev.ready = 1;
    client_wev.ready = client_wev.delayed = 1;

    // Redirect to http parser
    ngx_http_init_connection(c);

    // We do not provide working timers or events, and thus we have to manually
    // clean up the requests we created. We do this here.
    // Cross-referencing: https://trac.nginx.org/nginx/ticket/2080#no1).I
    // This is a fix that should be bettered in the future, by creating proper
    // timers and events.
    if (c->destroyed != 1) {
        if (c->read->data != NULL) {
            ngx_connection_t *c2 = (ngx_connection_t*)c->read->data;
            ngx_http_request_t *req_tmp = (ngx_http_request_t*)c2->data;
            req_tmp->cleanup = NULL;
            ngx_http_finalize_request(req_tmp, NGX_DONE);
        }
        ngx_close_connection(c);
    }
}
