#!/usr/bin/env bash

docker run \
	-it \
	--rm \
	-v $(pwd)/io:/io \
	--cap-add SYS_ADMIN \
	--security-opt seccomp=unconfined \
	--env='LC_ALL=en_US.UTF-8' \
	--network="host" \
	ctf_kali \
	/bin/zsh
