#pragma once

#include <vector>
#include <utility>

struct HPackCompressor {
    HPackCompressor() {}
    std::string compress(
            google::protobuf::RepeatedPtrField<h2proto::HeaderField> headers);
    int get_header_index(h2proto::HeaderField header);
    int get_name_index(h2proto::HeaderField header);
    void dynamic_table_add(h2proto::HeaderField header);
    void set_max_table_size(uint32_t size);

    void run_tests();

    /* HPACK Tables */
    typedef std::vector<std::pair<std::string, std::string>> header_list;
    header_list dynamic_table;
    uint32_t max_table_size = 4096;
    uint32_t table_size = 0;

    private:
    /* Make enum nicer to work with */
    enum Indexing {
        INCREMENTAL = h2proto::HeaderField_Indexing_INCREMENTAL,
        WITHOUT_INDEX = h2proto::HeaderField_Indexing_WITHOUT_INDEX,
        NEVER_INDEXED = h2proto::HeaderField_Indexing_NEVER_INDEXED
    };

    /* Literal indexing bit patterns. */
    static constexpr uint8_t literal_indexing_msbs[] = {
        [Indexing::INCREMENTAL]     = 0x40,
        [Indexing::WITHOUT_INDEX]   = 0x00,
        [Indexing::NEVER_INDEXED]   = 0x10
    };

    static constexpr uint8_t literal_indexing_prefixes[] = {
        [h2proto::HeaderField_Indexing_INCREMENTAL]     = 2,
        [h2proto::HeaderField_Indexing_WITHOUT_INDEX]   = 4,
        [h2proto::HeaderField_Indexing_NEVER_INDEXED]   = 4
    };


    /* See RFC 7541 Appendix A */
    const header_list static_table = {
        { ":authority", "" },
        { ":method", "GET" },
        { ":method", "POST" },
        { ":path", "/" },
        { ":path", "/index.html" },
        { ":scheme", "http" },
        { ":scheme", "https" },
        { ":status", "200" },
        { ":status", "204" },
        { ":status", "206" },
        { ":status", "304" },
        { ":status", "400" },
        { ":status", "404" },
        { ":status", "500" },
        { "accept-charset", "" },
        { "accept-encoding", "gzip, deflate" },
        { "accept-language", "" },
        { "accept-ranges", "" },
        { "accept", "" },
        { "access-control-allow-origin", "" },
        { "age", "" },
        { "allow", "" },
        { "authorization", "" },
        { "cache-control", "" },
        { "content-disposition", "" },
        { "content-encoding", "" },
        { "content-language", "" },
        { "content-length", "" },
        { "content-location", "" },
        { "content-range", "" },
        { "content-type", "" },
        { "cookie", "" },
        { "date", "" },
        { "etag", "" },
        { "expect", "" },
        { "expires", "" },
        { "from", "" },
        { "host", "" },
        { "if-match", "" },
        { "if-modified-since", "" },
        { "if-none-match", "" },
        { "if-range", "" },
        { "if-unmodified-since", "" },
        { "last-modified", "" },
        { "link", "" },
        { "location", "" },
        { "max-forwards", "" },
        { "proxy-authenticate", "" },
        { "proxy-authorization", "" },
        { "range", "" },
        { "referer", "" },
        { "refresh", "" },
        { "retry-after", "" },
        { "server", "" },
        { "set-cookie", "" },
        { "strict-transport-security", "" },
        { "transfer-encoding", "" },
        { "user-agent", "" },
        { "vary", "" },
        { "via", "" },
        { "www-authenticate", "" },
    };
};

/* Global HPACK instance */
extern HPackCompressor hpack_compressor;
