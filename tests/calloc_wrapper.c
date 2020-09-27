#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>

void *__real_calloc(size_t num, size_t size);
void *__wrap_calloc(size_t num, size_t size)
{
   int fail = (int) mock();

   if (fail) {
      return NULL;
   } else {
      return __real_calloc(num, size);
   }
}
