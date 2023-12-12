/*
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "yajl/yajl_tree.h"

static unsigned char fileData[65536];

int main(void)
{
    size_t rd;
    yajl_val node;
    char errbuf[1024];
    /* null plug buffers */
    fileData[0] = errbuf[0] = 0; 

    /* read the entire config file */
    rd = fread((void *) fileData, 1, sizeof(fileData) - 1, stdin);
    // length = read(STDIN_FILENO, input, SIZE);

    /* file read error handling */
    if (rd == 0 && !feof(stdin)) {
        fprintf(stderr, "error encountered on file read\n");
        return 1;
    } else if (rd >= sizeof(fileData) - 1) {
        fprintf(stderr, "config file too big\n");
        return 1;
    }

    while (__AFL_LOOP(10000)) {
        /* we have the whole config file in memory.  let's parse it ... */
        node = yajl_tree_parse((const char *) fileData, errbuf, sizeof(errbuf));

        /* parse error handling */
        if (node == NULL) {
            return 1;
        }

        yajl_tree_free(node);
    }

    return 0;
}
