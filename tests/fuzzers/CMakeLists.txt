# SPDX-FileCopyrightText: 2021 David Korczynski
#
# SPDX-License-Identifier: Apache-2.0

add_executable(fuzz_parser fuzz_parser.cpp)
target_link_libraries(fuzz_parser pistache_static)
set_target_properties(fuzz_parser PROPERTIES LINK_FLAGS $ENV{LIB_FUZZING_ENGINE})

add_executable(fuzz_server fuzz_server.cpp)
target_link_libraries(fuzz_server pistache_static)
set_target_properties(fuzz_server PROPERTIES LINK_FLAGS $ENV{LIB_FUZZING_ENGINE})

target_include_directories(fuzz_server PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
)
