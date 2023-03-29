#include <stdio.h>
#include <stdlib.h>

const char interp_section[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";

__attribute__((constructor)) void
_ctor_libabe(void)
{
  puts("Constructing Lib ABE 0.0.1");
}

__attribute__((destructor)) void
_dtor_libabe(void)
{
  puts("Destroying Lib ABE 0.0.1");
}

void winner(void)
{
  puts("ABE{this_is_a_demo_flag}");
}

void __libabe_main(void)
{
  puts("Lib ABE 0.0.1");
  exit(0);
}
