CC=gcc
CFLAGS=-no-pie -fno-stack-protector

# container
poc:

libabe.o: libabe.c
	$(CC) -fpic -c $< -o $@

libabe.so: libabe.o
	$(CC) -shared -nostartfiles --entry __libabe_main -o $@ $^

# host
.PHONY: ctf demo shell run_demo run_ctf
build_ctf: Dockerfile_ctf
	docker build -f $< -t challenge_dl .

build_demo: Dockerfile_demo
	docker build -f $< -t ctf_kali .

shell:
	./exec.sh

run_demo:
	./run_demo.sh

run_ctf:
	./run_ctf.sh

poc_ctf:
	docker create --name extract challenge_dl
	docker cp extract:/poc poc_ctf
	docker rm extract

