#!/usr/bin/env bash

docker build -t $(basename $PWD)-docker .
docker run --cap-add=SYS_PTRACE -it $(basename $PWD)-docker:latest
