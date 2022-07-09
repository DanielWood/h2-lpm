#pragma once
#include <string>
#include <algorithm>

template <typename T>
std::string Encode(const T& t) {
    Encode(t);
}

#define DECLARE_ENCODE_FUNCTION(TYPE, NAME) \
    template<> \
    std::string Encode<TYPE>(const TYPE& NAME)

#define PAD_H2_FRAME(FRAME, BUF, FLAGS) \
    if (FRAME.has_pad_length()) { \
        BUF.insert(0, 1, std::min(FRAME.pad_length(), (uint32_t)255)); \
        for (int i = 0; i < std::min(FRAME.pad_length(), (uint32_t)255); i++, BUF += (uint8_t)0); \
        FLAGS |= 0x8; \
    }

#define MAX_INT_31 ((uint32_t)0x7fffffff)

// Prototypes
std::string enframe(uint8_t type, uint8_t flags, uint32_t stream_id, std::string payload);
std::string pack_int(uint32_t value, unsigned int nbytes);

DECLARE_ENCODE_FUNCTION(h2proto::Sequence, sequence);
DECLARE_ENCODE_FUNCTION(h2proto::Frame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::DataFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::HPackInt, frame);
DECLARE_ENCODE_FUNCTION(h2proto::HPackString, frame);
DECLARE_ENCODE_FUNCTION(h2proto::HeadersFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::PriorityFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::RstStreamFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::SettingsFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::PushPromiseFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::PingFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::GoawayFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::WindowUpdateFrame, frame);
DECLARE_ENCODE_FUNCTION(h2proto::ContinuationFrame, frame);
