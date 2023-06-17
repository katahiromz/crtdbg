/*
 * PROJECT:     crtdbg (msvcrtd) clone
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Debuggable C Runtime
 * COPYRIGHT:   Copyright 2023 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <wchar.h>
#include <mbstring.h>
#include <direct.h>
#include <stdbool.h>
#include "crtdbg.h"
#include <windows.h>

/*---------------------*/

#undef malloc
#undef calloc
#undef realloc
#undef _recalloc
#undef _expand
#undef free
#undef _msize

#undef _aligned_malloc
#undef _aligned_realloc
#undef _aligned_recalloc
#undef _aligned_free
#undef _aligned_offset_malloc
#undef _aligned_offset_realloc
#undef _aligned_offset_recalloc

#undef _malloca
#undef _freea

#undef _strdup
#undef _wcsdup
#undef _mbsdup
#undef _tempnam
#undef _wtempnam
#undef _fullpath
#undef _wfullpath
#undef _getcwd
#undef _wgetcwd
#undef _getdcwd
#undef _wgetdcwd
#undef _getdcwd_nolock
#undef _wgetdcwd_nolock

/*---------------------*/

#undef _malloc_dbg
#undef _calloc_dbg
#undef _realloc_dbg
#undef _recalloc_dbg
#undef _expand_dbg
#undef _free_dbg
#undef _msize_dbg

#undef _aligned_malloc_dbg
#undef _aligned_realloc_dbg
#undef _aligned_recalloc_dbg
#undef _aligned_free_dbg
#undef _aligned_offset_malloc_dbg
#undef _aligned_offset_realloc_dbg
#undef _aligned_offset_recalloc_dbg

#undef _malloca_dbg
#undef _freea_dbg

#undef _strdup_dbg
#undef _wcsdup_dbg
#undef _mbsdup_dbg
#undef _tempnam_dbg
#undef _wtempnam_dbg
#undef _fullpath_dbg
#undef _wfullpath_dbg
#undef _getcwd_dbg
#undef _wgetcwd_dbg
#undef _getdcwd_dbg
#undef _wgetdcwd_dbg
#undef _getdcwd_lk_dbg
#undef _wgetdcwd_lk_dbg

/*---------------------*/

#undef _CrtSetReportHook
#undef _CrtGetReportHook
#undef _CrtSetReportHook2
#undef _CrtSetReportHookW2
#undef _CrtSetReportMode
#undef _CrtSetReportFile

#undef _CrtSetBreakAlloc
#undef _CrtSetAllocHook
#undef _CrtGetAllocHook
#undef _CrtCheckMemory
#undef _CrtSetDbgFlag
#undef _CrtDoForAllClientObjects
#undef _CrtIsValidPointer
#undef _CrtIsValidHeapPointer
#undef _CrtIsMemoryBlock
#undef _CrtReportBlockType
#undef _CrtSetDumpClient
#undef _CrtGetDumpClient
#undef _CrtMemCheckpoint
#undef _CrtMemDifference
#undef _CrtMemDumpAllObjectsSince
#undef _CrtMemDumpStatistics
#undef _CrtDumpMemoryLeaks
#undef _CrtSetDebugFillThreshold
#undef _CrtSetCheckCount
#undef _CrtGetCheckCount

/*---------------------*/

#undef _crtDbgFlag
#undef _crtDbgBreakAlloc

/*---------------------*/

#include <strsafe.h>
#include <assert.h>
#include "crtdbg-dev.h"
#include "xmalloc.h"
#define XASSERT(x) assert(x)

/*---------------------*/

void
DebugVPrintfA(const char *fmt, va_list va)
{
    char buf[1024];
    StringCchVPrintfA(buf, _countof(buf), fmt, va);
    OutputDebugStringA(buf);
}

void
DebugVPrintfW(const wchar_t *fmt, va_list va)
{
    wchar_t buf[1024];
    StringCchVPrintfW(buf, _countof(buf), fmt, va);
    OutputDebugStringW(buf);
}

void
DebugPrintfA(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    DebugVPrintfA(fmt, va);
    va_end(va);
}

void
DebugPrintfW(const wchar_t *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    DebugVPrintfW(fmt, va);
    va_end(va);
}

int* __m__crtDbgFlag(void)
{
    static int _crtDbgFlag = _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_DEFAULT_DF;
    return &_crtDbgFlag;
}

long* __m__crtBreakAlloc(void)
{
    static long _crtDbgBreakAlloc = -1;
    return &_crtDbgBreakAlloc;
}

static
_CrtMemBlockHeader *
header_from_block(const void * const block)
{
    return (_CrtMemBlockHeader*)((void*)(block)) - 1;
}

static
unsigned char *
block_from_header(const _CrtMemBlockHeader *header)
{
    return (unsigned char *)((_CrtMemBlockHeader *)(header) + 1);
}

static
bool
check_bytes(unsigned char *first, unsigned char value, size_t size)
{
    unsigned char *last = first + size;
    while (first != last)
    {
        if (*first != value)
            return false;
        ++first;
    }
    return true;
}

static bool
is_bad_read_ptr(const void *ptr, size_t size)
{
    if (ptr == NULL)
        return true;

    if (!(((size_t)ptr) & ~((size_t)0xFFFF)))
        return true;

    const char *first = (const char *)(ptr);
    const char *last = first + size;
    if (last < first)
        return true;

    SYSTEM_INFO SysInfo;
    GetSystemInfo(&SysInfo);

    // FIXME

    SysInfo.dwPageSize;
}

/*---------------------*/

MZCRTIMP
void *
__cdecl
_malloc_dbg(
    size_t size,
    int blockType,
    const char *file,
    int line)
{
    return malloc(size);
}

MZCRTIMP
void *
__cdecl
_calloc_dbg(
    size_t num,
    size_t size,
    int blockType,
    const char *file,
    int line)
{
    return calloc(num, size);
}

MZCRTIMP
void
__cdecl
_free_dbg(
    void *ptr,
    int blockType)
{
    free(ptr);
}

MZCRTIMP
void *
__cdecl
_realloc_dbg(
    void *ptr,
    size_t size,
    int blockType,
    const char *file,
    int line)
{
    return realloc(ptr, size);
}

#if 0
MZCRTIMP
void *
__cdecl
_recalloc_dbg(
    void *ptr,
    size_t num,
    size_t size,
    int blockType,
    const char *file,
    int line)
{
    return _recalloc(ptr, num, size);
}
#endif

MZCRTIMP
void *
__cdecl
_expand_dbg(
    void *ptr,
    size_t new_size,
    int blockType,
    const char *file,
    int line)
{
    return _expand(ptr, new_size);
}

MZCRTIMP
size_t
__cdecl
_msize_dbg(
    void *ptr,
    int blockType)
{
    return _msize(ptr);
}

MZCRTIMP
char *
__cdecl
_strdup_dbg(
    const char *str,
    int blockType,
    const char *file,
    int line)
{
    return _strdup(str);
}

MZCRTIMP
wchar_t *
__cdecl
_wcsdup_dbg(
    const wchar_t *str,
    int blockType,
    const char *file,
    int line)
{
    return _wcsdup(str);
}

MZCRTIMP
unsigned char *
__cdecl
_mbsdup_dbg(
    const unsigned char *str,
    int blockType,
    const char *file,
    int line)
{
    return _mbsdup(str);
}

MZCRTIMP
void *
__cdecl
_aligned_offset_malloc_dbg(
    size_t size,
    size_t alignment,
    size_t offset,
    const char *file,
    int line)
{
    return _aligned_offset_malloc(size, alignment, offset);
}

MZCRTIMP
void *
__cdecl
_aligned_offset_realloc_dbg(
    void *ptr,
    size_t size,
    size_t alignment,
    size_t offset,
    const char *file,
    int line)
{
    return _aligned_offset_realloc(ptr, size, alignment, offset);
}

#if 0
MZCRTIMP
void *
__cdecl
_aligned_offset_recalloc_dbg(
    void *ptr,
    size_t num,
    size_t size,
    size_t alignment,
    size_t offset,
    const char *file,
    int line)
{
    return _aligned_offset_recalloc(ptr, num, size, alignment, offset);
}
#endif

MZCRTIMP
void *
__cdecl
_aligned_malloc_dbg(
    size_t size,
    size_t alignment,
    const char *file,
    int line)
{
    return _aligned_malloc(size, alignment);
}

MZCRTIMP
void *
__cdecl
_aligned_realloc_dbg(
    void *ptr,
    size_t size,
    size_t alignment,
    const char *file,
    int line)
{
    return _aligned_realloc(ptr, size, alignment);
}

#if 0
MZCRTIMP
void *
__cdecl
_aligned_recalloc_dbg(
    void *ptr,
    size_t num,
    size_t size,
    size_t alignment,
    const char *file,
    int line)
{
    return _aligned_recalloc(ptr, num, size, alignment);
}
#endif

MZCRTIMP
void
__cdecl
_aligned_free_dbg(
    void *ptr)
{
    _aligned_free(ptr);
}

MZCRTIMP
void *
__cdecl
_malloca_dbg(
    size_t size,
    int blockType,
    const char *file,
    int line)
{
    return malloc(size);
}

MZCRTIMP
void
__cdecl
_freea_dbg(
    void *ptr,
    int blockType)
{
    free(ptr);
}

MZCRTIMP
char *
__cdecl
_tempnam_dbg(
    const char *dir,
    const char *prefix,
    int blockType,
    const char *file,
    int line)
{
    return _tempnam(dir, prefix);
}

MZCRTIMP
wchar_t *
__cdecl
_wtempnam_dbg(
    const wchar_t *dir,
    const wchar_t *prefix,
    int blockType,
    const char *file,
    int line)
{
    return _wtempnam(dir, prefix);
}

MZCRTIMP
char *
__cdecl
_fullpath_dbg(
    char *abspath,
    const char *relpath,
    size_t maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _fullpath(abspath, relpath, maxlen);
}

MZCRTIMP
wchar_t *
__cdecl
_wfullpath_dbg(
    wchar_t *abspath,
    const wchar_t *relpath,
    size_t maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _wfullpath(abspath, relpath, maxlen);
}

MZCRTIMP
char *
__cdecl
_getcwd_dbg(
    char *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _getcwd(buffer, maxlen);
}

MZCRTIMP
wchar_t *
__cdecl
_wgetcwd_dbg(
    wchar_t *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _wgetcwd(buffer, maxlen);
}

MZCRTIMP
char *
__cdecl
_getdcwd_dbg(
    int drive,
    char *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _getdcwd(drive, buffer, maxlen);
}

MZCRTIMP
wchar_t *
__cdecl
_wgetdcwd_dbg(
    int drive,
    wchar_t *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _wgetdcwd(drive, buffer, maxlen);
}

#if 0
MZCRTIMP
char *
__cdecl
_getdcwd_lk_dbg(
    int drive,
    char *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _getdcwd_nolock(drive, buffer, maxlen);
}

MZCRTIMP
wchar_t *
__cdecl
_wgetdcwd_lk_dbg(
    int drive,
    wchar_t *buffer,
    int maxlen,
    int blockType,
    const char *file,
    int line)
{
    return _wgetdcwd_nolock(drive, buffer, maxlen);
}
#endif

MZCRTIMP
_CRT_REPORT_HOOK
__cdecl
_CrtSetReportHook(
    _CRT_REPORT_HOOK reportHook)
{
    return NULL;
}

MZCRTIMP
_CRT_REPORT_HOOK
__cdecl
_CrtGetReportHook(void)
{
    return NULL;
}

MZCRTIMP
int
__cdecl
_CrtSetReportHook2(
    int mode,
    _CRT_REPORT_HOOK pfnNewHook)
{
    return 0;
}

MZCRTIMP
int
__cdecl
_CrtSetReportHookW2(
    int mode,
    _CRT_REPORT_HOOKW pfnNewHook)
{
    return 0;
}

MZCRTIMP
int
__cdecl
_CrtSetReportMode(
    int reportType,
    int reportMode)
{
    return 0;
}

MZCRTIMP
_HFILE
__cdecl
_CrtSetReportFile(
    int reportType,
    _HFILE reportFile)
{
    return NULL;
}

MZCRTIMP
long
__cdecl
_CrtSetBreakAlloc(
    long lBreakAlloc)
{
    return 0;
}

MZCRTIMP
_CRT_ALLOC_HOOK
__cdecl
_CrtSetAllocHook(
    _CRT_ALLOC_HOOK allocHook)
{
    return NULL;
}

MZCRTIMP
_CRT_ALLOC_HOOK
__cdecl
_CrtGetAllocHook(void)
{
    return NULL;
}

MZCRTIMP
int
__cdecl
_CrtCheckMemory(void)
{
    return 1;
}

static void MemDbg_atexit_leak_check(void)
{
    _CrtDumpMemoryLeaks();
}

MZCRTIMP
int
__cdecl
_CrtSetDbgFlag(
    int newFlag)
{
    static int s_registered_leak_check_at_exit = 0;
    const int c_valid_flags =
        _CRTDBG_ALLOC_MEM_DF |
        _CRTDBG_DELAY_FREE_MEM_DF |
        _CRTDBG_CHECK_ALWAYS_DF |
        _CRTDBG_CHECK_CRT_DF |
        _CRTDBG_LEAK_CHECK_DF;

    XASSERT((newFlag & ~c_valid_flags) == 0);

    if (newFlag & _CRTDBG_LEAK_CHECK_DF)
    {
        if (!s_registered_leak_check_at_exit)
        {
            atexit(MemDbg_atexit_leak_check);
            s_registered_leak_check_at_exit = 1;
        }
    }

    return 0;
}

MZCRTIMP
void
__cdecl
_CrtDoForAllClientObjects(
    void (*pfn)(void *, void *),
    void *context)
{
}

MZCRTIMP
int
__cdecl
_CrtIsValidPointer(
    const void *address,
    unsigned int size,
    int access)
{
    return (address != NULL);
}

MZCRTIMP
int
__cdecl
_CrtIsValidHeapPointer(
    const void *ptr)
{
    if (!ptr)
        return 0;
    return HeapValidate(GetProcessHeap(), 0, header_from_block(ptr));
}

MZCRTIMP
int
__cdecl
_CrtIsMemoryBlock(
    const void *ptr,
    unsigned int size,
    long *requestNumber,
    char **filename,
    int *lineNumber)
{
    return 1;
}

MZCRTIMP
int
__cdecl
_CrtReportBlockType(
    const void *pBlock)
{
    return -1;
}

MZCRTIMP
_CRT_DUMP_CLIENT
__cdecl
_CrtSetDumpClient(
    _CRT_DUMP_CLIENT dumpClient)
{
    return NULL;
}

MZCRTIMP
_CRT_DUMP_CLIENT
__cdecl
_CrtGetDumpClient(void)
{
    return NULL;
}

MZCRTIMP
void
__cdecl
_CrtMemCheckpoint(
    _CrtMemState *state)
{
}

MZCRTIMP
int
__cdecl
_CrtMemDifference(
    _CrtMemState *stateDiff,
    const _CrtMemState *oldState,
    const _CrtMemState *newState)
{
    return 0;
}

MZCRTIMP
void
__cdecl
_CrtMemDumpAllObjectsSince(
    const _CrtMemState *state)
{
}

MZCRTIMP
void
__cdecl
_CrtMemDumpStatistics(
    const _CrtMemState *state)
{
    XASSERT(state != NULL);

    if (state == NULL)
    {
        errno = EINVAL;
        return;
    }
}

MZCRTIMP
int
__cdecl
_CrtDumpMemoryLeaks(void)
{
    if (0)
    {
        DebugPrintfA(
            "Detected memory leaks!\n"
            "Dumping objects ->\n");

        for (int i = 0; i < 0; ++i)
        {
            //DebugPrintfA("%s(%d) : {%d} crt block at 0x%08X, subtype %d, %d bytes long.\n",
            //             __FILE__, __LINE__, block_index, (size_t)addr, subtype, bytes);
            //DebugPrintfA(" Data: <0123456789ABCDEF> DE D2 85 90 20 F7 23 90 20 F7 23 90 20 F7 23 90 \n");
        }

        DebugPrintfA("Object dump complete.\n");
    }
    return 0;
}

MZCRTIMP
size_t
__cdecl
_CrtSetDebugFillThreshold(
    size_t newThreshold)
{
    return 0;
}

MZCRTIMP
int
__cdecl
_CrtSetCheckCount(
    int fFlag)
{
    return 0;
}

MZCRTIMP
int
__cdecl
_CrtGetCheckCount(void)
{
    return 0;
}

MZCRTIMP
int
__cdecl
_CrtDbgReport(
    int reportType,
    const char *filename,
    int line,
    const char *moduleName,
    const char *format,
    ...)
{
    va_list va;
    static const char *s_reportTypes[] =
    {
        "warn", "err", "assert", "errcnt"
    };

    XASSERT(reportType < _countof(s_reportTypes));

    va_start(va, format);
    DebugPrintfA("%s (%d): module '%s': %s: ",
                 filename, line, moduleName, s_reportTypes[reportType]);
    DebugVPrintfA(format, va);

    if (reportType >= _CRT_ASSERT)
        XASSERT(0);

    va_end(va);

    return 0;
}

MZCRTIMP
int
__cdecl
_CrtDbgReportW(
    int reportType,
    const wchar_t *filename,
    int line,
    const wchar_t *moduleName,
    const wchar_t *format,
    ...)
{
    va_list va;
    static const wchar_t *s_reportTypes[] =
    {
        L"warn", L"err", L"assert", L"errcnt"
    };

    XASSERT(reportType < _countof(s_reportTypes));

    va_start(va, format);
    DebugPrintfW(L"%s (%d): module '%s': %s: ",
                 filename, line, moduleName, s_reportTypes[reportType]);
    DebugVPrintfW(format, va);

    if (reportType >= _CRT_ASSERT)
        XASSERT(0);

    va_end(va);

    return 0;
}

/*---------------------*/
