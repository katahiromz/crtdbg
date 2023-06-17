#pragma once

#define XMALLOC(size)           malloc(size)
#define XCALLOC(nelem, size)    calloc((nelem), (size))
#define XFREE(ptr)              free(ptr)
#define XREALLOC(ptr, size)     realloc((ptr), (size))
#define XMSIZE(ptr)             _msize(ptr)
