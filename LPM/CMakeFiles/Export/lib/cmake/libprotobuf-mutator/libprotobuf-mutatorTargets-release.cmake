#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "libprotobuf-mutator::protobuf-mutator-libfuzzer" for configuration "Release"
set_property(TARGET libprotobuf-mutator::protobuf-mutator-libfuzzer APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libprotobuf-mutator::protobuf-mutator-libfuzzer PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libprotobuf-mutator-libfuzzer.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS libprotobuf-mutator::protobuf-mutator-libfuzzer )
list(APPEND _IMPORT_CHECK_FILES_FOR_libprotobuf-mutator::protobuf-mutator-libfuzzer "${_IMPORT_PREFIX}/lib/libprotobuf-mutator-libfuzzer.a" )

# Import target "libprotobuf-mutator::protobuf-mutator" for configuration "Release"
set_property(TARGET libprotobuf-mutator::protobuf-mutator APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libprotobuf-mutator::protobuf-mutator PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libprotobuf-mutator.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS libprotobuf-mutator::protobuf-mutator )
list(APPEND _IMPORT_CHECK_FILES_FOR_libprotobuf-mutator::protobuf-mutator "${_IMPORT_PREFIX}/lib/libprotobuf-mutator.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
