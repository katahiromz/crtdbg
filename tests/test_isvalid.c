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
    _CrtMemDumpStatistics(NULL);

    void *ptr = calloc(10, 1);
    assert(_CrtIsValidPointer(ptr, 1, 0));
    assert(_CrtIsValidPointer(ptr, 0x7FFFFFF, 0));
    assert(_CrtIsValidHeapPointer(ptr));
    //free(ptr);

    ptr = (void *)(size_t)1;
    assert(_CrtIsValidPointer(ptr, 1, 0));
    assert(_CrtIsValidPointer(ptr, 0x7FFFFFF, 0));
    //assert(_CrtIsValidHeapPointer(ptr));

    static const char data[] = { 1 };
    ptr = (void *)data;
    assert(_CrtIsValidPointer(ptr, 1, 0));
    assert(_CrtIsValidPointer(ptr, 0x7FFFFFF, 0));
    assert(_CrtIsValidPointer(ptr, 1, 1));
    assert(_CrtIsValidPointer(ptr, 0x7FFFFFF, 1));
    //assert(_CrtIsValidHeapPointer(ptr));

    return 0;
}
