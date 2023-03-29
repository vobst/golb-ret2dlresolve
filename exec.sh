#!/usr/bin/env bash

CID=$(docker container list -lq)

docker exec \
	-it \
	--env='LC_ALL=en_US.UTF-8' \
	${CID} \
	/bin/zsh
