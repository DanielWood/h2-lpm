#include <string>
#include <algorithm>

#include "h2_frame_grammar.pb.h"
#include "h2_sequence.pb.h"

#include "protobuf_encoders.h"
#include "hpack_compressor.h"

/* Frame Sequence */
DECLARE_ENCODE_FUNCTION(h2proto::Sequence, sequence)
{
    std::string buf;// = Encode(sequence.settings_frame());
    for (auto frame : sequence.frames()) buf += Encode(frame);

    return buf;
}


/* Frame Wrapper */
DECLARE_ENCODE_FUNCTION(h2proto::Frame, frame)
{
    // Pls compile 2 jump table
    using enum h2proto::Frame::FrameOneofCase;
    switch (frame.frame_oneof_case()) {
        case kDataFrame: return Encode(frame.data_frame());
        case kHeadersFrame: return Encode(frame.headers_frame());
        case kPriorityFrame: return Encode(frame.priority_frame());
        case kRstStreamFrame: return Encode(frame.rst_stream_frame());
        case kSettingsFrame: return Encode(frame.settings_frame());
        case kPushPromiseFrame: return Encode(frame.push_promise_frame());
        case kPingFrame: return Encode(frame.ping_frame());
        case kGoawayFrame: return Encode(frame.goaway_frame());
        case kWindowUpdateFrame: return Encode(frame.window_update_frame());
        case kContinuationFrame: return Encode(frame.continuation_frame());
    }

    return std::string();
}


/* HPack Integers.
 * FIXME: Remove 64 bit size limit. Might find some bugs in the long bois.
 */
DECLARE_ENCODE_FUNCTION(h2proto::HPackInt, integer)
{
    std::string buf;

    uint8_t msb_mask = std::min(integer.msb_mask(), (uint32_t)255);
    int prefix = std::max(integer.prefix(), (uint32_t)8);
    uint8_t max = (1 << prefix) - 1;

    if (integer.value() < max) {
        buf += integer.value() | msb_mask;
        return buf;
    }

    uint64_t running = integer.value();
    running -= max;
    buf += max | msb_mask;

    while (running >= 128) {
        buf += (running % 128 + 128);
        running /= 128;
    }

    buf += running;
    return buf;
}


/* HPack Strings. */
DECLARE_ENCODE_FUNCTION(h2proto::HPackString, str)
{
#include "huffman.h"

    std::string buf;

    // With Huffman coding
    if (str.huffman()) {
        int octet_offset = 0;
        for (auto c : str.data())
        {
            HuffmanCode code = huffman_table[c];

            for (int i = 0; i < code.bit_len; i += 8)
            {
                int remaining_bits = 0;
                uint8_t dat;

                if (code.bit_len > i + 8) {
                    dat = (code.code >> (code.bit_len - 8 - i));
                } else {
                    dat = code.code;
                    remaining_bits = (32 - code.bit_len) % 8;
                }

                if (octet_offset == 0) {
                    buf += dat << remaining_bits;
                } else {
                    if (code.bit_len > octet_offset) {
                        uint32_t shift = std::min(code.bit_len, (uint32_t)8) -
                                octet_offset;

                        buf.back() |= dat >> shift;

                        // There are still bits to write

                        // If we are carrying over from another byte
                        if (i > 0)
                            dat &= (2 << (8 - shift)) - 1;

                        buf += dat << (8 - shift);
                    }
                    else
                        buf.back() |= dat << (octet_offset - code.bit_len);
                }

                // Recalculate offset
                octet_offset += remaining_bits;
                octet_offset %= 8;
            }
        }

        // EOS padding
        if (octet_offset) {
            buf.back() |= 0xff >> (8 - octet_offset);
        }
    }
    else {
        // Without huffman coding
        buf += str.data();
    }

    h2proto::HPackInt length;
    length.set_value(buf.size());
    length.set_prefix(7);
    length.set_msb_mask(str.huffman() << 7);
    buf.insert(0, Encode(length));

    return buf;
}


/* Frame Type 0: DATA */
DECLARE_ENCODE_FUNCTION(h2proto::DataFrame, frame)
{
    std::string buf = frame.data();
    uint8_t flags = frame.end_stream() << 0;

    PAD_H2_FRAME(frame, buf, flags);
    return enframe(0, flags, frame.stream_id(), buf);
}


/* Frame Type 1: HEADERS */

DECLARE_ENCODE_FUNCTION(h2proto::HeadersFrame, frame)
{
    std::string buf;
    uint8_t flags = 0;

    // Stream dependency
    if (frame.has_stream_dependency()) {
        std::string packed = pack_int(frame.stream_dependency(), 4);
        buf += (frame.exclusive() << 7) | (packed[0] & ~(1 << 7));
        buf += packed.substr(1);
        flags |= 0x20;
    }

    buf += hpack_compressor.compress(frame.header_list());

    PAD_H2_FRAME(frame, buf, flags);

    return enframe(1, flags, frame.stream_id(), buf);
}


/* Frame Type 2: PRIORITY */
DECLARE_ENCODE_FUNCTION(h2proto::PriorityFrame, frame)
{
    std::string buf, packed = pack_int(frame.stream_dependency(), 4);
    buf += (frame.exclusive() << 7) | (packed[0] & ~(1 << 7));
    buf += packed.substr(1);
    buf += std::min(frame.weight(), (uint32_t)255);

    return enframe(2, 0, 0, buf);
}


/* Frame Type 3: RST_STREAM */
DECLARE_ENCODE_FUNCTION(h2proto::RstStreamFrame, frame)
{
    return enframe(3, 0, 0, pack_int(frame.error_code(), 4));
}


/* Frame Type 4: SETTINGS */
DECLARE_ENCODE_FUNCTION(h2proto::SettingsFrame, frame)
{
    std::string buf;
    uint8_t flags = frame.ack();

    // Params
    if (!frame.ack())
    {
        std::vector<std::pair<uint32_t, uint32_t>> parameters;
        if (frame.has_header_table_size())
            parameters.push_back({ 1, frame.header_table_size() });

        if (frame.has_enable_push())
            parameters.push_back({ 2, frame.enable_push() });

        if (frame.has_max_concurrent_streams())
            parameters.push_back({ 3, frame.max_concurrent_streams() });

        if (frame.has_initial_window_size())
            parameters.push_back({ 4, frame.initial_window_size() });

        if (frame.has_max_frame_size())
            parameters.push_back({ 5, frame.max_frame_size() });

        if (frame.has_max_header_list_size())
            parameters.push_back({ 6, frame.max_header_list_size() });

        for (auto param : parameters) {
            buf += pack_int(std::get<0>(param), 2);
            buf += pack_int(std::get<1>(param), 4);
        }
    }

    return enframe(4, flags, 0, buf);
}


/* Frame Type 5: PUSH_PROMISE */
DECLARE_ENCODE_FUNCTION(h2proto::PushPromiseFrame, frame)
{
    std::string buf;
    uint8_t flags = frame.end_headers() << 2;

    buf += pack_int(std::min(frame.promised_stream_id(), MAX_INT_31), 4);
    buf += hpack_compressor.compress(frame.header_list());

    PAD_H2_FRAME(frame, buf, flags);

    return enframe(5, flags, frame.stream_id(), buf);
}


/* Frame Type 6: PING */
DECLARE_ENCODE_FUNCTION(h2proto::PingFrame, frame)
{
    std::string buf;
    uint8_t flags = frame.ack();

    buf += pack_int(frame.opaque_data_lo(), 4);
    buf += pack_int(frame.opaque_data_hi(), 4);

    return enframe(6, flags, 0, buf);
}


/* Frame Type 7: GOAWAY */
DECLARE_ENCODE_FUNCTION(h2proto::GoawayFrame, frame)
{
    std::string buf;

    buf += pack_int(std::min(frame.last_stream_id(), MAX_INT_31), 4);
    buf += pack_int(frame.error_code(), 4);
    
    if (frame.has_opaque_data()) {
        buf += frame.opaque_data();
    }

    return enframe(7, 0, 0, buf);
}


/* Frame Type 8: WINDOW_UPDATE */
DECLARE_ENCODE_FUNCTION(h2proto::WindowUpdateFrame, frame)
{
    std::string buf;

    buf += pack_int(std::min(frame.window_size_increment(), MAX_INT_31), 4);

    return enframe(8, 0, 0, buf);
}


/* Frame Type 9: CONTINUATION */
DECLARE_ENCODE_FUNCTION(h2proto::ContinuationFrame, frame)
{
    std::string buf;
    uint8_t flags = frame.end_headers() << 2;

    buf += hpack_compressor.compress(frame.header_list());

    return enframe(9, flags, frame.stream_id(), buf);
}

/* Helpers */
std::string enframe(uint8_t type, uint8_t flags, uint32_t stream_id, std::string payload)
{
    std::string header;
    header += pack_int(payload.size(), 3);
    header += type;
    header += flags;
    header += pack_int(std::min(stream_id, MAX_INT_31), 4);

    return header + payload;
}

std::string pack_int(uint32_t value, unsigned int nbytes)
{
    std::string buf;
    for (int i = nbytes - 1; i >= 0; i--) {
        buf += (value >> (i * 8)) & 0xff;
    }

    return buf;
}
