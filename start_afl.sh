#! /usr/bin/bash

sudo docker run --rm -ti --mount type=bind,source=.,target=/mnt-host aflplusplus/aflplusplus
