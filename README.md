# ret2dlresolve & its friends

This is the repository accompanying my blog post on the dynamic linker (DL). Click [here](https://eb9f.de/2023/03/29/ret2dlresolve.html) to read the full post.

## How to use this repository

You will need `Docker` and `make` installed on the host system.

Run `make build_demo && make run_demo` to build and run a Docker container that comes with everything you need to explore the techniques described in the 
*Runtime - ret2dlresolve, ret2dl_open_worker & DynELF* section of the post.
- `demo.py` contains an exploit for the `poc` binary that uses ret2dlresolve to call `system("/bin/sh")`, as well as
  the code to use `DynELF` to dump the DL from the remote process
- `solution.py` uses the offset between `_dl_runtime_resolve` and `dl_open_worker`, which we can obtain from the dumped DL, to open `libabe.so` and
  call the `winner` function

There is also an example CTF challenge that attempts to highlight some strengths of the techniques described in the post.
Use `make build_ctf && make run_ctf` to run the `poc` binary in a root file system that contains nothing but the DL, libc and libabe.
You can choose any distribution and version for the *builder* container to convince yourself that the technique does not require knowledge
of the exact execution environment. You will, however, need to reverse engineer the offset of `dl_open_worker` from the dumped DL for each OS and version.

To play with the `sudo --backdoor` from the post, you will need to clone [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), install the 
dependencies, copy the `insecurexec.*` files to `libbpf-bootstrap/examples/c/`, add `insecureexec` to `APPS` in the `Makefile` and build the program
using `make insecurexec`.
