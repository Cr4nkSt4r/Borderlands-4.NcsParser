cmake_minimum_required(VERSION 3.20)

project(ncs_parser LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_SUPPRESS_REGENERATION true)
set(USE_CLANG_FORMAT true)


add_library(ncs_lib STATIC
    src/ncs/ncs_bit_writer.h
    src/ncs_parser.cpp
    src/ncs_parser.h
    src/common.h
    src/utils/fs_utils.cpp
    src/utils/fs_utils.h
    src/utils/log.cpp
    src/utils/log.h
    src/utils/blake3_stub.c
    src/ncs/ncs_bit_reader.h
    src/ncs/ncs_crc32.cpp
    src/ncs/ncs_crc32.h
    src/ncs/ncs_decomp.cpp
    src/ncs/ncs_decomp.h
    src/ncs/ncs_decomp_writer.cpp
    src/ncs/ncs_decomp_writer.h
    src/ncs/ncs_file.cpp
    src/ncs/ncs_file.h
    src/ncs/ncs_table_data_encoder.cpp
    src/ncs/ncs_table_data_encoder.h
    src/ncs/ncs_type_code_table.cpp
    src/ncs/ncs_type_code_table.h
    src/ncs/ncs_table_data_decoder.cpp
    src/ncs/ncs_table_data_decoder.h
    src/oodle/oodle_api.cpp
    src/oodle/oodle_api.h
    third_party/blake3/blake3.c
    third_party/blake3/blake3_portable.c
)

add_executable(ncs_parser
    src/main.cpp
)

target_include_directories(ncs_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3
)

if(USE_CLANG_FORMAT)
    if(DEFINED ENV{CLANG_FORMAT_PATH} AND NOT "$ENV{CLANG_FORMAT_PATH}" STREQUAL "")
        set(CLANG_FORMAT_PATH "$ENV{CLANG_FORMAT_PATH}" CACHE FILEPATH "Path to clang-format binary" FORCE)
    else()
        find_program(CLANG_FORMAT_PATH NAMES clang-format)
    endif()

    if(CLANG_FORMAT_PATH)
        get_target_property(NCSLIB_SOURCES ncs_lib SOURCES)
        add_custom_command(
            TARGET ncs_lib
            PRE_BUILD
            COMMENT "Running clang-format on ncs_lib"
            COMMAND ${CLANG_FORMAT_PATH} -i ${NCSLIB_SOURCES}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        get_target_property(NCPARSER_SOURCES ncs_parser SOURCES)
        add_custom_command(
            TARGET ncs_parser
            PRE_BUILD
            COMMENT "Running clang-format on ncs_parser"
            COMMAND ${CLANG_FORMAT_PATH} -i ${NCSLIB_SOURCES}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    else() 
        message(WARNING "clang-format path Envar \"CLANG_FORMAT_PATH\" not set!")
    endif()
else()
  message(WARNING "clang-format disabled!")
endif()

if (WIN32)
    target_compile_definitions(ncs_lib PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_link_libraries(ncs_lib PUBLIC dl)
endif()

target_link_libraries(ncs_parser PRIVATE ncs_lib)
set_target_properties(ncs_lib PROPERTIES OUTPUT_NAME "ncs")
