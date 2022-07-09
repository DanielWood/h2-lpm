
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <signal.h>
}

#include <iostream>
#include <fstream>
#include <cstdio>

#include "nginx_harness.h"
#include "h2_sequence.pb.h"
#include "h2_frame_grammar.pb.h"
#include "protobuf_encoders.h"
#include "hpack_compressor.h"
#include "src/libfuzzer/libfuzzer_macro.h"

// Helpers
h2proto::HPackString _hstr(std::string data, bool force_literal = false,
        bool huffman = false)
{
    h2proto::HPackString str;
    str.set_data(data);
    str.set_force_literal(force_literal);
    str.set_huffman(huffman);
    return str;
}

h2proto::HeaderField _hdr(h2proto::HPackString name,
        h2proto::HPackString value, h2proto::HeaderField_Indexing indexing)
{
    h2proto::HeaderField hdr;
    *hdr.mutable_name() = name;
    *hdr.mutable_value() = value;
    hdr.set_indexing(indexing);
    return hdr;
}

int main()
{
    static int init = setup_nginx();
    assert(init == 0);

    auto request = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    std::string response;

    h2proto::Conversation conversation;
    std::ifstream input(
            "/home/ufo/personal/research/fuzzing/nginx/crash-959e8bb0cdcb723c7e512ff07d9f003dbf93b1f4");
    std::string str((std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());

    if (!google::protobuf::TextFormat::ParseFromString(str, &conversation)) {
        std::cerr << "Failed to parse conversation\n";
        return -1;
    }

    for (auto ex : conversation.exchanges()) {
        request += Encode(ex.request_sequence());
        response += Encode(ex.request_sequence());
    }

    // Initial request settings

    //req_seq.mutable_settings_frame()->set_max_frame_size((1 << 23) - 2);
    //req_seq.mutable_settings_frame()->set_ack(false);

    /* Initial headers frame
    {
        h2proto::HeadersFrame hf;
        hf.set_end_headers(true);
        hf.set_stream_id(1);

        // The headers
        *hf.mutable_header_list()->Add() = _hdr(
                _hstr(":authority"),
                _hstr("area0x33.mil", true, true),
                h2proto::HeaderField_Indexing_INCREMENTAL);

        *hf.mutable_header_list()->Add() = _hdr(
                _hstr(":authority"),
                _hstr("area0x33.mil", false, false),
                h2proto::HeaderField_Indexing_INCREMENTAL);

        h2proto::Frame frame;
        *frame.mutable_headers_frame() = hf;
        *req_seq.mutable_frames()->Add() = frame;
    }


    // Trailing goaway
    {
        h2proto::GoawayFrame goaway;
        goaway.set_last_stream_id(1);
        goaway.set_error_code(0);

        h2proto::Frame frame;
        *frame.mutable_goaway_frame() = goaway;
        *req_seq.mutable_frames()->Add() = frame;
    }*/

    //request += Encode(req_seq);

    std::cout << request;
    set_nginx_request(request);
    set_nginx_response(response);

    // Create event and connection
    ngx_event_t client_rev = {};
    ngx_event_t client_wev = {};
    ngx_connection_t client_local = {
        .read = &client_rev,
        .write = &client_wev,
        .send_chain = send_chain
    };

    ngx_event_t server_rev = {};
    ngx_event_t server_wev = {};
    ngx_connection_t server_local = {
        .read = &server_rev,
        .write = &server_wev,
        .send_chain = send_chain
    };

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

    return 0;
}
