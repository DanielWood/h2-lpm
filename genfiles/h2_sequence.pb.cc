// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: h2_sequence.proto

#include "h2_sequence.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace h2proto {
constexpr Sequence::Sequence(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : frames_(){}
struct SequenceDefaultTypeInternal {
  constexpr SequenceDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~SequenceDefaultTypeInternal() {}
  union {
    Sequence _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT SequenceDefaultTypeInternal _Sequence_default_instance_;
constexpr Exchange::Exchange(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : request_sequence_(nullptr)
  , response_sequence_(nullptr){}
struct ExchangeDefaultTypeInternal {
  constexpr ExchangeDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~ExchangeDefaultTypeInternal() {}
  union {
    Exchange _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT ExchangeDefaultTypeInternal _Exchange_default_instance_;
constexpr Conversation::Conversation(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : exchanges_(){}
struct ConversationDefaultTypeInternal {
  constexpr ConversationDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~ConversationDefaultTypeInternal() {}
  union {
    Conversation _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT ConversationDefaultTypeInternal _Conversation_default_instance_;
}  // namespace h2proto
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_h2_5fsequence_2eproto[3];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_h2_5fsequence_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_h2_5fsequence_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_h2_5fsequence_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::h2proto::Sequence, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::h2proto::Sequence, frames_),
  PROTOBUF_FIELD_OFFSET(::h2proto::Exchange, _has_bits_),
  PROTOBUF_FIELD_OFFSET(::h2proto::Exchange, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::h2proto::Exchange, request_sequence_),
  PROTOBUF_FIELD_OFFSET(::h2proto::Exchange, response_sequence_),
  0,
  1,
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::h2proto::Conversation, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::h2proto::Conversation, exchanges_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::h2proto::Sequence)},
  { 6, 13, sizeof(::h2proto::Exchange)},
  { 15, -1, sizeof(::h2proto::Conversation)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::h2proto::_Sequence_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::h2proto::_Exchange_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::h2proto::_Conversation_default_instance_),
};

const char descriptor_table_protodef_h2_5fsequence_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\021h2_sequence.proto\022\007h2proto\032\026h2_frame_g"
  "rammar.proto\"*\n\010Sequence\022\036\n\006frames\030\001 \003(\013"
  "2\016.h2proto.Frame\"e\n\010Exchange\022+\n\020request_"
  "sequence\030\001 \002(\0132\021.h2proto.Sequence\022,\n\021res"
  "ponse_sequence\030\002 \002(\0132\021.h2proto.Sequence\""
  "4\n\014Conversation\022$\n\texchanges\030\001 \003(\0132\021.h2p"
  "roto.Exchange"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_h2_5fsequence_2eproto_deps[1] = {
  &::descriptor_table_h2_5fframe_5fgrammar_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_h2_5fsequence_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_h2_5fsequence_2eproto = {
  false, false, 253, descriptor_table_protodef_h2_5fsequence_2eproto, "h2_sequence.proto", 
  &descriptor_table_h2_5fsequence_2eproto_once, descriptor_table_h2_5fsequence_2eproto_deps, 1, 3,
  schemas, file_default_instances, TableStruct_h2_5fsequence_2eproto::offsets,
  file_level_metadata_h2_5fsequence_2eproto, file_level_enum_descriptors_h2_5fsequence_2eproto, file_level_service_descriptors_h2_5fsequence_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_h2_5fsequence_2eproto_getter() {
  return &descriptor_table_h2_5fsequence_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_h2_5fsequence_2eproto(&descriptor_table_h2_5fsequence_2eproto);
namespace h2proto {

// ===================================================================

class Sequence::_Internal {
 public:
};

void Sequence::clear_frames() {
  frames_.Clear();
}
Sequence::Sequence(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned),
  frames_(arena) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:h2proto.Sequence)
}
Sequence::Sequence(const Sequence& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      frames_(from.frames_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:h2proto.Sequence)
}

inline void Sequence::SharedCtor() {
}

Sequence::~Sequence() {
  // @@protoc_insertion_point(destructor:h2proto.Sequence)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void Sequence::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void Sequence::ArenaDtor(void* object) {
  Sequence* _this = reinterpret_cast< Sequence* >(object);
  (void)_this;
}
void Sequence::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Sequence::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Sequence::Clear() {
// @@protoc_insertion_point(message_clear_start:h2proto.Sequence)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  frames_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Sequence::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated .h2proto.Frame frames = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_frames(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Sequence::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:h2proto.Sequence)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .h2proto.Frame frames = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_frames_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(1, this->_internal_frames(i), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:h2proto.Sequence)
  return target;
}

size_t Sequence::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:h2proto.Sequence)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .h2proto.Frame frames = 1;
  total_size += 1UL * this->_internal_frames_size();
  for (const auto& msg : this->frames_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Sequence::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    Sequence::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Sequence::GetClassData() const { return &_class_data_; }

void Sequence::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<Sequence *>(to)->MergeFrom(
      static_cast<const Sequence &>(from));
}


void Sequence::MergeFrom(const Sequence& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:h2proto.Sequence)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  frames_.MergeFrom(from.frames_);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Sequence::CopyFrom(const Sequence& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:h2proto.Sequence)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Sequence::IsInitialized() const {
  if (!::PROTOBUF_NAMESPACE_ID::internal::AllAreInitialized(frames_)) return false;
  return true;
}

void Sequence::InternalSwap(Sequence* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  frames_.InternalSwap(&other->frames_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Sequence::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_h2_5fsequence_2eproto_getter, &descriptor_table_h2_5fsequence_2eproto_once,
      file_level_metadata_h2_5fsequence_2eproto[0]);
}

// ===================================================================

class Exchange::_Internal {
 public:
  using HasBits = decltype(std::declval<Exchange>()._has_bits_);
  static const ::h2proto::Sequence& request_sequence(const Exchange* msg);
  static void set_has_request_sequence(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static const ::h2proto::Sequence& response_sequence(const Exchange* msg);
  static void set_has_response_sequence(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static bool MissingRequiredFields(const HasBits& has_bits) {
    return ((has_bits[0] & 0x00000003) ^ 0x00000003) != 0;
  }
};

const ::h2proto::Sequence&
Exchange::_Internal::request_sequence(const Exchange* msg) {
  return *msg->request_sequence_;
}
const ::h2proto::Sequence&
Exchange::_Internal::response_sequence(const Exchange* msg) {
  return *msg->response_sequence_;
}
Exchange::Exchange(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:h2proto.Exchange)
}
Exchange::Exchange(const Exchange& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      _has_bits_(from._has_bits_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  if (from._internal_has_request_sequence()) {
    request_sequence_ = new ::h2proto::Sequence(*from.request_sequence_);
  } else {
    request_sequence_ = nullptr;
  }
  if (from._internal_has_response_sequence()) {
    response_sequence_ = new ::h2proto::Sequence(*from.response_sequence_);
  } else {
    response_sequence_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:h2proto.Exchange)
}

inline void Exchange::SharedCtor() {
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&request_sequence_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&response_sequence_) -
    reinterpret_cast<char*>(&request_sequence_)) + sizeof(response_sequence_));
}

Exchange::~Exchange() {
  // @@protoc_insertion_point(destructor:h2proto.Exchange)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void Exchange::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  if (this != internal_default_instance()) delete request_sequence_;
  if (this != internal_default_instance()) delete response_sequence_;
}

void Exchange::ArenaDtor(void* object) {
  Exchange* _this = reinterpret_cast< Exchange* >(object);
  (void)_this;
}
void Exchange::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Exchange::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Exchange::Clear() {
// @@protoc_insertion_point(message_clear_start:h2proto.Exchange)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      GOOGLE_DCHECK(request_sequence_ != nullptr);
      request_sequence_->Clear();
    }
    if (cached_has_bits & 0x00000002u) {
      GOOGLE_DCHECK(response_sequence_ != nullptr);
      response_sequence_->Clear();
    }
  }
  _has_bits_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Exchange::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // required .h2proto.Sequence request_sequence = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr = ctx->ParseMessage(_internal_mutable_request_sequence(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // required .h2proto.Sequence response_sequence = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_response_sequence(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  _has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Exchange::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:h2proto.Exchange)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // required .h2proto.Sequence request_sequence = 1;
  if (cached_has_bits & 0x00000001u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        1, _Internal::request_sequence(this), target, stream);
  }

  // required .h2proto.Sequence response_sequence = 2;
  if (cached_has_bits & 0x00000002u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::response_sequence(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:h2proto.Exchange)
  return target;
}

size_t Exchange::RequiredFieldsByteSizeFallback() const {
// @@protoc_insertion_point(required_fields_byte_size_fallback_start:h2proto.Exchange)
  size_t total_size = 0;

  if (_internal_has_request_sequence()) {
    // required .h2proto.Sequence request_sequence = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *request_sequence_);
  }

  if (_internal_has_response_sequence()) {
    // required .h2proto.Sequence response_sequence = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *response_sequence_);
  }

  return total_size;
}
size_t Exchange::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:h2proto.Exchange)
  size_t total_size = 0;

  if (((_has_bits_[0] & 0x00000003) ^ 0x00000003) == 0) {  // All required fields are present.
    // required .h2proto.Sequence request_sequence = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *request_sequence_);

    // required .h2proto.Sequence response_sequence = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *response_sequence_);

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Exchange::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    Exchange::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Exchange::GetClassData() const { return &_class_data_; }

void Exchange::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<Exchange *>(to)->MergeFrom(
      static_cast<const Exchange &>(from));
}


void Exchange::MergeFrom(const Exchange& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:h2proto.Exchange)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _internal_mutable_request_sequence()->::h2proto::Sequence::MergeFrom(from._internal_request_sequence());
    }
    if (cached_has_bits & 0x00000002u) {
      _internal_mutable_response_sequence()->::h2proto::Sequence::MergeFrom(from._internal_response_sequence());
    }
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Exchange::CopyFrom(const Exchange& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:h2proto.Exchange)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Exchange::IsInitialized() const {
  if (_Internal::MissingRequiredFields(_has_bits_)) return false;
  if (_internal_has_request_sequence()) {
    if (!request_sequence_->IsInitialized()) return false;
  }
  if (_internal_has_response_sequence()) {
    if (!response_sequence_->IsInitialized()) return false;
  }
  return true;
}

void Exchange::InternalSwap(Exchange* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(Exchange, response_sequence_)
      + sizeof(Exchange::response_sequence_)
      - PROTOBUF_FIELD_OFFSET(Exchange, request_sequence_)>(
          reinterpret_cast<char*>(&request_sequence_),
          reinterpret_cast<char*>(&other->request_sequence_));
}

::PROTOBUF_NAMESPACE_ID::Metadata Exchange::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_h2_5fsequence_2eproto_getter, &descriptor_table_h2_5fsequence_2eproto_once,
      file_level_metadata_h2_5fsequence_2eproto[1]);
}

// ===================================================================

class Conversation::_Internal {
 public:
};

Conversation::Conversation(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned),
  exchanges_(arena) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:h2proto.Conversation)
}
Conversation::Conversation(const Conversation& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      exchanges_(from.exchanges_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:h2proto.Conversation)
}

inline void Conversation::SharedCtor() {
}

Conversation::~Conversation() {
  // @@protoc_insertion_point(destructor:h2proto.Conversation)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void Conversation::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void Conversation::ArenaDtor(void* object) {
  Conversation* _this = reinterpret_cast< Conversation* >(object);
  (void)_this;
}
void Conversation::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Conversation::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Conversation::Clear() {
// @@protoc_insertion_point(message_clear_start:h2proto.Conversation)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  exchanges_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Conversation::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated .h2proto.Exchange exchanges = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_exchanges(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Conversation::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:h2proto.Conversation)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .h2proto.Exchange exchanges = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_exchanges_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(1, this->_internal_exchanges(i), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:h2proto.Conversation)
  return target;
}

size_t Conversation::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:h2proto.Conversation)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .h2proto.Exchange exchanges = 1;
  total_size += 1UL * this->_internal_exchanges_size();
  for (const auto& msg : this->exchanges_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Conversation::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    Conversation::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Conversation::GetClassData() const { return &_class_data_; }

void Conversation::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<Conversation *>(to)->MergeFrom(
      static_cast<const Conversation &>(from));
}


void Conversation::MergeFrom(const Conversation& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:h2proto.Conversation)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  exchanges_.MergeFrom(from.exchanges_);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Conversation::CopyFrom(const Conversation& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:h2proto.Conversation)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Conversation::IsInitialized() const {
  if (!::PROTOBUF_NAMESPACE_ID::internal::AllAreInitialized(exchanges_)) return false;
  return true;
}

void Conversation::InternalSwap(Conversation* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  exchanges_.InternalSwap(&other->exchanges_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Conversation::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_h2_5fsequence_2eproto_getter, &descriptor_table_h2_5fsequence_2eproto_once,
      file_level_metadata_h2_5fsequence_2eproto[2]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace h2proto
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::h2proto::Sequence* Arena::CreateMaybeMessage< ::h2proto::Sequence >(Arena* arena) {
  return Arena::CreateMessageInternal< ::h2proto::Sequence >(arena);
}
template<> PROTOBUF_NOINLINE ::h2proto::Exchange* Arena::CreateMaybeMessage< ::h2proto::Exchange >(Arena* arena) {
  return Arena::CreateMessageInternal< ::h2proto::Exchange >(arena);
}
template<> PROTOBUF_NOINLINE ::h2proto::Conversation* Arena::CreateMaybeMessage< ::h2proto::Conversation >(Arena* arena) {
  return Arena::CreateMessageInternal< ::h2proto::Conversation >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
