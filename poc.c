#include <unistd.h>

void main(void)
{
  char b;
  read(0, &b, 0x1337);
}
