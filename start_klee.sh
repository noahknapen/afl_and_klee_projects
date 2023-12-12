#! /usr/bin/bash

sudo docker run --rm -ti --ulimit='stack=-1:-1' --mount type=bind,source=.,target=/mnt-host klee/klee
