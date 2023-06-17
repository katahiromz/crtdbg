#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <crtdbg.h>

int main(void)
{
    _CrtSetDbgFlag(
        _CRTDBG_ALLOC_MEM_DF |
        _CRTDBG_DELAY_FREE_MEM_DF |
        _CRTDBG_CHECK_ALWAYS_DF |
        //_CRTDBG_RESERVED_DF |
        _CRTDBG_CHECK_CRT_DF |
        _CRTDBG_LEAK_CHECK_DF |
        0);

    void *ptr = calloc(10, 1);
    ptr = realloc(ptr, 20);
    printf("_msize: %d\n", (int)_msize(ptr));
    free(ptr);
    ptr = realloc(NULL, 20);
    printf("_msize: %d\n", (int)_msize(ptr));
    ptr = realloc(ptr, 0);
    assert(ptr == NULL);
    return 0;
}
