#include <string>
#include <vector>
#include <utility>
#include <algorithm>

#include "h2_frame_grammar.pb.h"
#include "h2_sequence.pb.h"
#include "hpack_compressor.h"
#include "protobuf_encoders.h"

/* Global HPACK instance */
HPackCompressor hpack_compressor;

std::string HPackCompressor::compress(
        google::protobuf::RepeatedPtrField<h2proto::HeaderField> headers)
{
    std::string buf;
    for (auto header : headers)
    {
        h2proto::HPackString name = header.name();
        h2proto::HPackString value = header.value();

        h2proto::HPackInt magic;
        magic.set_prefix(literal_indexing_prefixes[header.indexing()]);
        magic.set_msb_mask(literal_indexing_msbs[header.indexing()]);

        int header_idx = get_header_index(header);
        int name_idx = get_name_index(header);

        // Literal Header Field
        if (!name_idx || name.force_literal()) {
            magic.set_value(0);
            buf += Encode(magic);
            buf += Encode(name);
            buf += Encode(value);

            if (header.indexing() == Indexing::INCREMENTAL) {
                dynamic_table_add(header);
            }
        }
        // Indexed Name + Literal Value
        else if (name_idx && !header_idx) {
            magic.set_value(name_idx);
            buf += Encode(magic);
            buf += Encode(value);

            if (header.indexing() == Indexing::INCREMENTAL) {
                dynamic_table_add(header);
            }
        }
        // Indexed Header Field
        else if (header_idx) {
            h2proto::HPackInt idx;
            idx.set_prefix(7);
            idx.set_msb_mask(1 << 7);
            idx.set_value(header_idx);
            buf += Encode(idx);
        }
    }

    return buf;
}

void HPackCompressor::dynamic_table_add(h2proto::HeaderField header)
{
    std::pair<std::string, std::string> entry = {
        header.name().data(),
        header.value().data()
    };

    dynamic_table.insert(dynamic_table.begin(), entry);

    table_size += header.name().data().size();
    table_size += header.value().data().size();
    table_size += 32;

    // Evict old entries when table gets too large
    while (table_size > max_table_size) {
        if (dynamic_table.size() < 1) {
            table_size = 0;
        } else {
            auto evict = dynamic_table.back();
            dynamic_table.pop_back();

            table_size -= std::get<0>(evict).size();
            table_size -= std::get<1>(evict).size();
            table_size -= 32;
        }
    }
}

int HPackCompressor::get_header_index(h2proto::HeaderField header)
{
    std::pair<std::string, std::string> field = {
        header.name().data(),
        header.value().data()
    };

    // Check static table
    {
        auto it = find(static_table.begin(), static_table.end(), field);
        if (it != static_table.end()) {
            return 1 + (it - static_table.begin());
        }
    }

    // Check dynamic table
    {
        auto it = find(dynamic_table.begin(), dynamic_table.end(), field);
        if (it != dynamic_table.end()) {
            return 1 + (it - dynamic_table.begin()) + static_table.size();
        }
    }

    return 0;
}


int HPackCompressor::get_name_index(h2proto::HeaderField header)
{
    std::string name = header.name().data();

    // Check static table
    for (int i = 0; i < static_table.size(); i++) {
        if (name == std::get<0>(static_table[i])) {
            return 1 + i;
        }
    }

    // Check dynamic table
    for (int i = 0; i < dynamic_table.size(); i++) {
        if (name == std::get<0>(dynamic_table[i])) {
            return 1 + static_table.size() + i;
        }
    }

    return 0;
}

void HPackCompressor::run_tests()
{
    // Single indexed header
    {
        HPackCompressor _hpack;

        std::vector<h2proto::HeaderField> headers;
        h2proto::HeaderField method;
        method.mutable_name()->set_data(":method");
        method.mutable_name()->set_force_literal(false);
        method.mutable_name()->set_huffman(false);
        method.mutable_value()->set_data("GET");
        method.mutable_value()->set_force_literal(false);
        method.mutable_value()->set_huffman(false);
        headers.push_back(method);

        google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
        proto_headers.Add(headers.begin(), headers.end());
        std::string indexed = _hpack.compress(proto_headers);
        assert(indexed == "\x82");
    }

    // RFC7541 C.3 - Request Examples without Huffman Coding
    {
        HPackCompressor _hpack;

        // Request 1
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("http");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(false);
            headers.push_back(authority);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_one = _hpack.compress(proto_headers);
            assert(request_one == "\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d");
            assert(std::get<0>(_hpack.dynamic_table[0]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "www.example.com");
            assert(_hpack.table_size == 57);
        }


        // Request 2
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("http");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(false);
            headers.push_back(authority);

            h2proto::HeaderField cache_control;
            cache_control.mutable_name()->set_data("cache-control");
            cache_control.mutable_name()->set_force_literal(false);
            cache_control.mutable_name()->set_huffman(false);
            cache_control.mutable_value()->set_data("no-cache");
            cache_control.mutable_value()->set_force_literal(false);
            cache_control.mutable_value()->set_huffman(false);
            headers.push_back(cache_control);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_two = _hpack.compress(proto_headers);
            assert(request_two == "\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65");
            assert(std::get<0>(_hpack.dynamic_table[0]) == "cache-control");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "no-cache");
            assert(std::get<0>(_hpack.dynamic_table[1]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[1]) == "www.example.com");
            assert(_hpack.table_size == 110);
        }

        // Request 3
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("https");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/index.html");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(false);
            headers.push_back(authority);

            h2proto::HeaderField custom_key;
            custom_key.mutable_name()->set_data("custom-key");
            custom_key.mutable_name()->set_force_literal(false);
            custom_key.mutable_name()->set_huffman(false);
            custom_key.mutable_value()->set_data("custom-value");
            custom_key.mutable_value()->set_force_literal(false);
            custom_key.mutable_value()->set_huffman(false);
            headers.push_back(custom_key);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_three = _hpack.compress(proto_headers);
            assert(request_three == "\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65");
            assert(std::get<0>(_hpack.dynamic_table[0]) == "custom-key");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "custom-value");
            assert(std::get<0>(_hpack.dynamic_table[1]) == "cache-control");
            assert(std::get<1>(_hpack.dynamic_table[1]) == "no-cache");
            assert(std::get<0>(_hpack.dynamic_table[2]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[2]) == "www.example.com");
            assert(_hpack.table_size == 164);
        }
    }

    // RFC7541 C.3 - Request Examples with Huffman Coding
    {
        HPackCompressor _hpack;

        // Request 1
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("http");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(true);
            headers.push_back(authority);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_one = _hpack.compress(proto_headers);
            assert(request_one == "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");
            assert(std::get<0>(_hpack.dynamic_table[0]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "www.example.com");
            assert(_hpack.table_size == 57);
        }

        // Request 2
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("http");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(true);
            headers.push_back(authority);

            h2proto::HeaderField cache_control;
            cache_control.mutable_name()->set_data("cache-control");
            cache_control.mutable_name()->set_force_literal(false);
            cache_control.mutable_name()->set_huffman(false);
            cache_control.mutable_value()->set_data("no-cache");
            cache_control.mutable_value()->set_force_literal(false);
            cache_control.mutable_value()->set_huffman(true);
            headers.push_back(cache_control);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_two = _hpack.compress(proto_headers);
            assert(request_two == "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf");
            assert(std::get<0>(_hpack.dynamic_table[0]) == "cache-control");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "no-cache");
            assert(std::get<0>(_hpack.dynamic_table[1]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[1]) == "www.example.com");
            assert(_hpack.table_size == 110);
        }

        // Request 3
        {
            std::vector<h2proto::HeaderField> headers;
            h2proto::HeaderField method;
            method.mutable_name()->set_data(":method");
            method.mutable_name()->set_force_literal(false);
            method.mutable_name()->set_huffman(false);
            method.mutable_value()->set_data("GET");
            method.mutable_value()->set_force_literal(false);
            method.mutable_value()->set_huffman(false);
            headers.push_back(method);

            h2proto::HeaderField scheme;
            scheme.mutable_name()->set_data(":scheme");
            scheme.mutable_name()->set_force_literal(false);
            scheme.mutable_name()->set_huffman(false);
            scheme.mutable_value()->set_data("https");
            scheme.mutable_value()->set_force_literal(false);
            scheme.mutable_value()->set_huffman(false);
            headers.push_back(scheme);

            h2proto::HeaderField path;
            path.mutable_name()->set_data(":path");
            path.mutable_name()->set_force_literal(false);
            path.mutable_name()->set_huffman(false);
            path.mutable_value()->set_data("/index.html");
            path.mutable_value()->set_force_literal(false);
            path.mutable_value()->set_huffman(false);
            headers.push_back(path);

            h2proto::HeaderField authority;
            authority.mutable_name()->set_data(":authority");
            authority.mutable_name()->set_force_literal(false);
            authority.mutable_name()->set_huffman(false);
            authority.mutable_value()->set_data("www.example.com");
            authority.mutable_value()->set_force_literal(false);
            authority.mutable_value()->set_huffman(true);
            headers.push_back(authority);

            h2proto::HeaderField custom_key;
            custom_key.mutable_name()->set_data("custom-key");
            custom_key.mutable_name()->set_force_literal(false);
            custom_key.mutable_name()->set_huffman(true);
            custom_key.mutable_value()->set_data("custom-value");
            custom_key.mutable_value()->set_force_literal(false);
            custom_key.mutable_value()->set_huffman(true);
            headers.push_back(custom_key);

            google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
            proto_headers.Add(headers.begin(), headers.end());
            std::string request_three = _hpack.compress(proto_headers);
            assert(request_three == "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf");
            assert(std::get<0>(_hpack.dynamic_table[0]) == "custom-key");
            assert(std::get<1>(_hpack.dynamic_table[0]) == "custom-value");
            assert(std::get<0>(_hpack.dynamic_table[1]) == "cache-control");
            assert(std::get<1>(_hpack.dynamic_table[1]) == "no-cache");
            assert(std::get<0>(_hpack.dynamic_table[2]) == ":authority");
            assert(std::get<1>(_hpack.dynamic_table[2]) == "www.example.com");
            assert(_hpack.table_size == 164);
        }
    }

    // Custom testing multi-byte Huffman codes
    {
        HPackCompressor _hpack;

        std::vector<h2proto::HeaderField> headers;
        h2proto::HeaderField custom_key;
        custom_key.mutable_name()->set_data("custom-key");
        custom_key.mutable_name()->set_force_literal(false);
        custom_key.mutable_name()->set_huffman(true);
        custom_key.mutable_value()->set_data("[huffmancodeme]lol");
        custom_key.mutable_value()->set_force_literal(false);
        custom_key.mutable_value()->set_huffman(true);
        headers.push_back(custom_key);

        google::protobuf::RepeatedPtrField<h2proto::HeaderField> proto_headers;
        proto_headers.Add(headers.begin(), headers.end());
        std::string request_one = _hpack.compress(proto_headers);
        assert(request_one == "\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x8f\xff\xdc\xf6\xcb\x2d\x23\xa8\x87\x90\xb4\x97\xff\x94\x1e\x8f");
    }

}
