# Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

SET (SRCS parse_config.c)

# use the library we build, duh.
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/../${YAJL_DIST_NAME}/include)
LINK_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/../${YAJL_DIST_NAME}/lib)

ADD_EXECUTABLE(parse_config ${SRCS})
ADD_EXECUTABLE(persistent_parse_config persistent_parse_config.c)

TARGET_LINK_LIBRARIES(parse_config yajl_s)
TARGET_LINK_LIBRARIES(persistent_parse_config yajl_s)
