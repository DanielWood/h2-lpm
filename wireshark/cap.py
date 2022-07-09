import json
import pdb
import struct
import time
from pprint import pprint #devonly

from google.protobuf import text_format
from h2_sequence_pb2 import Conversation, Exchange, Sequence
from h2_frame_grammar_pb2 import (Frame,
                                  DataFrame,
                                  HPackString,
                                  HeaderField,
                                  HeadersFrame,
                                  PriorityFrame,
                                  RstStreamFrame,
                                  SettingsFrame,
                                  PushPromiseFrame,
                                  PingFrame,
                                  GoawayFrame,
                                  WindowUpdateFrame,
                                  ContinuationFrame)

# Credit: ferdymercury
# https://stackoverflow.com/a/61416215
def array_on_duplicate_keys(ordered_pairs):
    '''Convert duplicate keys to arrays.'''
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            if type(d[k]) is list:
                d[k].append(v)
            else:
                d[k] = [d[k],v]
        else:
            d[k] = v
    return d

def ensure_list(obj):
    if type(obj) != list:
        return [obj]
    else:
        return obj

def decode_ws(data):
    '''Decode bytes in wireshark format'''
    return bytes([int(c, 16) for c in data.split(':')])

def encode_data_frame(stream):
    frame = Frame()
    df = frame.data_frame
    df.SetInParent()

    df.stream_id = int(stream['http2.streamid'])
    data = stream.get('http2.data.data')
    if data:
        df.data = decode_ws(data)
    else:
        df.data = b''

    # Set flags
    flags_tree = stream['http2.flags_tree']
    df.end_stream = flags_tree['http2.flags.end_stream'] == '1'

    if 'http2.pad_length' in stream:
        df.pad_length = int(stream['http2.pad_length'])

    return frame

def encode_headers_frame(stream):
    frame = Frame()
    hf = frame.headers_frame
    hf.SetInParent()

    # Header fields
    for header in stream.get('http2.header', []):
        field = HeaderField()
        field.name.data = header['http2.header.name'].encode()
        field.value.data = header['http2.header.value'].encode()

        # Field representation / indexing
        # Defaults
        field.value.force_literal = False
        field.name.force_literal = False
        field.value.huffman = False
        field.name.huffman = False
        field.indexing = HeaderField.INCREMENTAL

        _repr = header['http2.header.repr']
        if _repr.endswith('Indexed Name'):
            field.value.force_literal = True
        elif _repr.endswith('New Name'):
            field.name.force_literal = True
            field.value.force_literal = True

        if 'Incremental Indexing' in _repr:
            field.indexing = HeaderField.INCREMENTAL
        elif 'without Indexing' in _repr:
            field.indexing = HeaderField.WITHOUT_INDEX

        hf.header_list.append(field)

    hf.stream_id = int(stream['http2.streamid'])

    # set flags
    flags_tree = stream['http2.flags_tree']
    hf.end_stream = flags_tree['http2.flags.end_stream'] == '1'
    hf.end_headers = flags_tree['http2.flags.eh'] == '1'
    hf.priority = flags_tree['http2.flags.priority'] == '1'

    hf.exclusive = stream.get('http2.exclusive', '0') == '1'
    hf.stream_dependency = int(stream.get('http2.stream_dependency', '0'))
    hf.weight = int(stream.get('http2.headers.weight', '0'))

    if 'http2.pad_length' in stream:
        hf.pad_length = int(stream['http2.pad_length'])

    return frame

def encode_priority_frame(stream):
    frame = Frame()
    pf = frame.priority_frame
    pf.SetInParent()

    pf.exclusive = stream['http2.exclusive'] == '1'
    pf.stream_id = int(stream['http2.streamid'])
    pf.stream_dependency = int(stream['http2.stream_dependency'])
    pf.weight = int(stream['http2.headers.weight'])

    return frame

def encode_rst_stream_frame(stream):
    frame = Frame()
    rf = frame.rst_stream_frame
    rf.SetInParent()

    rf.error_code = int(stream['http2.rst_stream.error'])
    rf.stream_id = int(stream['http2.streamid'])

    return frame

def encode_settings_frame(stream):
    frame = Frame()
    sf = frame.settings_frame
    sf.SetInParent()

    if stream['http2.flags_tree']['http2.flags.ack.settings'] == '0':
        for setting in ensure_list(stream['http2.settings']):
            if 'http2.settings.header_table_size' in setting:
                sf.header_table_size = int(
                    setting['http2.settings.header_table_size'])
            if 'http2.settings.enable_push' in setting:
                sf.enable_push = bool(
                    setting['http2.settings.enable_push'])
            if 'http2.settings.max_concurrent_streams' in setting:
                sf.max_concurrent_streams = int(
                    setting['http2.settings.max_concurrent_streams'])
            if 'http2.settings.initial_window_size' in setting:
                sf.initial_window_size = int(
                    setting['http2.settings.initial_window_size'])
            if 'http2.settings.max_frame_size' in setting:
                sf.max_frame_size = int(
                    setting['http2.settings.max_frame_size'])
            if 'http2.settings.max_header_list_size' in setting:
                sf.max_header_list_size = int(
                    setting['http2.settings.max_header_list_size'])
        sf.ack = False
    else:
        sf.ack = True

    return frame

def encode_push_promise_frame(stream):
    frame = Frame()
    pf = frame.push_promise_frame
    pf.SetInParent()

    # So far never encountered???
    # TODO: Implement this
    pdb.set_trace()

    return frame

def encode_ping_frame(stream):
    frame = Frame()
    pf = frame.ping_frame
    pf.SetInParent()

    data = decode_ws(stream.get('http2.ping', stream.get('http2.pong')))
    pf.opaque_data_lo, = struct.unpack('I', data[:4])
    pf.opaque_data_hi, = struct.unpack('I', data[4:])

    pf.ack = stream['http2.flags_tree']['http2.flags.ack.ping'] == '1'

    return frame

def encode_goaway_frame(stream):
    frame = Frame()
    gf = frame.goaway_frame
    gf.SetInParent()


    gf.last_stream_id = int(stream['http2.goaway.last_stream_id'])
    gf.error_code = int(stream['http2.goaway.error'])

    # TODO: Find out the debug data key (not seen)
    if len(stream.keys()) != 9:
        pdb.set_trace()

    return frame

def encode_window_update_frame(stream):
    frame = Frame()
    wf = frame.window_update_frame
    wf.SetInParent()

    wf.window_size_increment = int(
        stream['http2.window_update.window_size_increment'])

    return frame

def encode_continuation_frame(stream):
    frame = Frame()
    cf = frame.continuation_frame
    cf.SetInParent()

    # TODO: Continuation frame not seen at all!
    pdb.set_trace()

    return frame


encoders = {
    '0': encode_data_frame,
    '1': encode_headers_frame,
    '2': encode_priority_frame,
    '3': encode_rst_stream_frame,
    '4': encode_settings_frame,
    '5': encode_push_promise_frame,
    '6': encode_ping_frame,
    '7': encode_goaway_frame,
    '8': encode_window_update_frame,
    '9': encode_continuation_frame
}

if __name__ == '__main__':
    body = None
    with open('cap.json') as f:
        body = json.load(f, object_pairs_hook=array_on_duplicate_keys)

    conversations = {}

    for _frame in body:
        layers = _frame['_source']['layers']

        if 'http2' in layers:
            # Attribute frames to tcp stream & http2 party
            tcp_stream = layers['tcp']['tcp.stream']
            is_client = layers['tcp']['tcp.srcport'] != '443'

            # New conversation per TCP stream
            if tcp_stream not in conversations:
                conversations[tcp_stream] = Conversation()
                conversations[tcp_stream].exchanges.append(Exchange())

            # Create new TCP exchange when req/res sequences are non-empty
            exchange = conversations[tcp_stream].exchanges[-1]
            if exchange.request_sequence.frames and exchange.response_sequence.frames:
                conversations[tcp_stream].exchanges.append(Exchange())

            # Iterate TCP streams
            http2 = ensure_list(layers['http2'])
            for h2val in http2:
                streams = ensure_list(h2val['http2.stream'])

                for stream in streams:
                    # Encode frames
                    if 'http2.type' in stream:
                        if stream['http2.type'] in encoders.keys():
                            encoded_frame = encoders[stream['http2.type']](stream)

                            if is_client:
                                exchange.request_sequence.frames.append(encoded_frame)
                            else:
                                exchange.response_sequence.frames.append(encoded_frame)

            # Write convos
            i = 0
            for conversation in conversations.values():
                # Skip unusable conversations
                if not any(map(lambda e: e.request_sequence.frames and
                           e.response_sequence.frames, conversation.exchanges)):
                    continue

                # Remove empty exchanges
                for exchange in conversation.exchanges:
                    if (not exchange.request_sequence.frames and
                        not exchange.response_sequence.frames):
                        conversation.exchanges.remove(exchange)

                with open(f'seed_corpus/seed_{int(time.time())}_{i}.txt', 'w') as f:
                    f.write(text_format.MessageToString(conversation))

                i += 1
