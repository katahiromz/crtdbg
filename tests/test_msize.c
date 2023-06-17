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

    void *ptr = NULL;
    _msize(ptr);
    _msize((void *)(size_t)1);
    ptr = malloc(1);
    _msize(ptr);
    free(ptr);
    _msize(ptr);
    return 0;
}
