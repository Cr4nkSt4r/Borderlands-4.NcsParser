cmake_minimum_required(VERSION 3.20)

project(NcsParser LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_SUPPRESS_REGENERATION true)

add_executable(NcsParser
    src/main.cpp
    src/common.h
    src/utils/fs_utils.cpp
    src/utils/fs_utils.h
    src/utils/log.cpp
    src/utils/log.h
    src/oodle/oodle_api.cpp
    src/oodle/oodle_api.h
    src/blake3/blake3_stub.c
    third_party/blake3/blake3.c
    third_party/blake3/blake3_portable.c
)

target_include_directories(NcsParser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3
)

if (WIN32)
    target_compile_definitions(NcsParser PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_link_libraries(NcsParser PRIVATE dl)
endif()

set(OODLE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/oodle")
if (WIN32)
    if (EXISTS "${OODLE_DIR}/oo2core_9_win64.dll")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            add_custom_command(TARGET NcsParser POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OODLE_DIR}/oo2core_9_win64.dll"
                    "$<TARGET_FILE_DIR:NcsParser>/oo2core_9_win64.dll")
        else()
            message(WARNING "NcsParser: 32-bit Windows build selected; no bundled Oodle DLL is provided.")
        endif()
    endif()
elseif(UNIX AND NOT APPLE)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(OODLE_LINUX_FILE "liboo2corelinuxarm64.so.9")
    else()
        set(OODLE_LINUX_FILE "liboo2corelinux64.so.9")
    endif()

    if (EXISTS "${OODLE_DIR}/${OODLE_LINUX_FILE}")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            add_custom_command(TARGET NcsParser POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OODLE_DIR}/${OODLE_LINUX_FILE}"
                    "$<TARGET_FILE_DIR:NcsParser>/${OODLE_LINUX_FILE}")
        else()
            message(WARNING "NcsParser: 32-bit Linux build selected; no bundled Oodle library is provided.")
        endif()
    endif()
endif()
