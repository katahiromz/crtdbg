#pragma once

#ifndef _INC_CRTDBG
#define _INC_CRTDBG

#ifdef __cplusplus
    #include <cstddef>
#else
    #include <stddef.h>
#endif

#ifdef MZCRT_DLL
    #ifdef MZCRT_BUILD
        #define MZCRTIMP __declspec(dllexport)
    #else
        #define MZCRTIMP __declspec(dllimport)
    #endif
#else
    #define MZCRTIMP
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* _HFILE;

#define _CRT_WARN   0
#define _CRT_ERROR  1
#define _CRT_ASSERT 2
#define _CRT_ERRCNT 3

#define _CRTDBG_MODE_FILE   1
#define _CRTDBG_MODE_DEBUG  2
#define _CRTDBG_MODE_WNDW   4

#define _CRTDBG_REPORT_MODE (-1)

#define _CRTDBG_INVALID_HFILE ((_HFILE)(intptr_t)-1)
#define _CRTDBG_HFILE_ERROR   ((_HFILE)(intptr_t)-2)
#define _CRTDBG_FILE_STDOUT   ((_HFILE)(intptr_t)-4)
#define _CRTDBG_FILE_STDERR   ((_HFILE)(intptr_t)-5)
#define _CRTDBG_REPORT_FILE   ((_HFILE)(intptr_t)-6)

typedef int (__cdecl* _CRT_REPORT_HOOK )(int, char*, int*);
typedef int (__cdecl* _CRT_REPORT_HOOKW)(int, wchar_t*, int*);

#define _CRT_RPTHOOK_INSTALL  0
#define _CRT_RPTHOOK_REMOVE   1

#define _HOOK_ALLOC    1
#define _HOOK_REALLOC  2
#define _HOOK_FREE     3

typedef int (__cdecl* _CRT_ALLOC_HOOK)(int, void*, size_t, int, long, const unsigned char *, int);

/* Bits for _crtDbgFlag */
#define _CRTDBG_ALLOC_MEM_DF        0x00000001 /* Turn on debug allocation */
#define _CRTDBG_DELAY_FREE_MEM_DF   0x00000002 /* Don't actually free memory */
#define _CRTDBG_CHECK_ALWAYS_DF     0x00000004 /* Check heap every alloc/dealloc */
#define _CRTDBG_RESERVED_DF         0x00000008 /* Reserved - do not use */
#define _CRTDBG_CHECK_CRT_DF        0x00000010 /* Leak check/diff CRT blocks */
#define _CRTDBG_LEAK_CHECK_DF       0x00000020 /* Leak check at program exit */
#define _CRTDBG_CHECK_EVERY_16_DF   0x00100000 /* Check heap every 16 heap ops */
#define _CRTDBG_CHECK_EVERY_128_DF  0x00800000 /* Check heap every 128 heap ops */
#define _CRTDBG_CHECK_EVERY_1024_DF 0x04000000 /* Check heap every 1024 heap ops */

#define _CRTDBG_CHECK_DEFAULT_DF    0          /* Don't check the heap */

#define _CRTDBG_REPORT_FLAG         -1

#define _BLOCK_TYPE(block)    ((block) & 0xFFFF)
#define _BLOCK_SUBTYPE(block) ((block) >> 16 & 0xFFFF)

/* Block types */
#define _FREE_BLOCK     0
#define _NORMAL_BLOCK   1
#define _CRT_BLOCK      2
#define _IGNORE_BLOCK   3
#define _CLIENT_BLOCK   4
#define _MAX_BLOCKS     5
#define _UNKNOWN_BLOCK  (-1)

typedef void (__cdecl* _CRT_DUMP_CLIENT)(void*, size_t);

struct _CrtMemBlockHeader;

typedef struct _CrtMemState
{
    struct _CrtMemBlockHeader *pBlockHeader;
    size_t lCounts[_MAX_BLOCKS];
    size_t lSizes[_MAX_BLOCKS];
    size_t lHighWaterCount;
    size_t lTotalCount;
} _CrtMemState;

#ifndef _DEBUG
    #define _CrtSetDbgFlag(f)              ((int)0)
    #define _CrtSetBreakAlloc(v)           ((long)0)
    #define _CrtGetCheckCount()            ((int)0)
    #define _CrtSetCheckCount(f)           ((int)0)
    #define _CrtGetAllocHook()             ((_CRT_ALLOC_HOOK)0)
    #define _CrtSetAllocHook(h)            ((_CRT_ALLOC_HOOK)0)
    #define _CrtGetDumpClient()            ((_CRT_DUMP_CLIENT)0)
    #define _CrtSetDumpClient(d)           ((_CRT_DUMP_CLIENT)0)
    #define _CrtCheckMemory()              ((int)1)
    #define _CrtDoForAllClientObjects(f,c) ((void)0)
    #define _CrtDumpMemoryLeaks()          ((int)0)
    #define _CrtIsMemoryBlock(p,s,r,f,l)   ((int)1)
    #define _CrtIsValidHeapPointer(p)      ((int)1)
    #define _CrtIsValidPointer(p,s,a)      ((int)1)
    #define _CrtMemCheckpoint(s)           ((void)0)
    #define _CrtMemDifference(d,o,n)       ((int)0)
    #define _CrtMemDumpAllObjectsSince(s)  ((void)0)
    #define _CrtMemDumpStatistics(s)       ((void)0)
    #define _CrtReportBlockType(p)         ((int)-1)
#else /* def _DEBUG */
    MZCRTIMP int*  __cdecl __m__crtDbgFlag(void);
    MZCRTIMP long* __cdecl __m__crtBreakAlloc(void);

    #define _crtDbgFlag    (*__m__crtDbgFlag())
    #define _crtBreakAlloc (*__m__crtBreakAlloc())

    MZCRTIMP int __cdecl _CrtSetDbgFlag(int newFlag);
    MZCRTIMP long __cdecl _CrtSetBreakAlloc(long newValue);
    MZCRTIMP int __cdecl _CrtGetCheckCount(void);
    MZCRTIMP int __cdecl _CrtSetCheckCount(int fFlag);
    MZCRTIMP _CRT_ALLOC_HOOK __cdecl _CrtGetAllocHook(void);
    MZCRTIMP _CRT_ALLOC_HOOK __cdecl _CrtSetAllocHook(_CRT_ALLOC_HOOK fnAlloc);
    MZCRTIMP _CRT_DUMP_CLIENT __cdecl _CrtGetDumpClient(void);
    MZCRTIMP _CRT_DUMP_CLIENT __cdecl _CrtSetDumpClient(_CRT_DUMP_CLIENT dumpClient);
    MZCRTIMP int __cdecl _CrtCheckMemory(void);

    typedef void (__cdecl* _CrtDoForAllClientObjectsCallback)(void*, void*);
    MZCRTIMP void __cdecl _CrtDoForAllClientObjects(void (*pfn)(void *, void *), void *context);
    MZCRTIMP int __cdecl _CrtDumpMemoryLeaks(void);
    MZCRTIMP int __cdecl _CrtIsMemoryBlock(const void *ptr, unsigned int size, long *requestNumber,
                                           char **filename, int *lineNumber);
    MZCRTIMP int __cdecl _CrtIsValidHeapPointer(const void *ptr);
    MZCRTIMP int __cdecl _CrtIsValidPointer(const void *address, unsigned int size, int access);
    MZCRTIMP void __cdecl _CrtMemCheckpoint(_CrtMemState *state);
    MZCRTIMP int __cdecl _CrtMemDifference(_CrtMemState *stateDiff, const _CrtMemState *oldState,
                                           const _CrtMemState *newState);
    MZCRTIMP void __cdecl _CrtMemDumpAllObjectsSince(const _CrtMemState *state);
    MZCRTIMP void __cdecl _CrtMemDumpStatistics(const _CrtMemState *state);
    MZCRTIMP int __cdecl _CrtReportBlockType(const void *block);
#endif /* def _DEBUG */

/* --------------------------------------------
 * Debug heap routines
 */

#ifndef _DEBUG
    #define _malloc_dbg(size, block, file, line) malloc(size)
    #define _calloc_dbg(num, size, block, file, line) calloc((num), (size))
    #define _free_dbg(ptr, block) free(ptr)
    #define _realloc_dbg(ptr, size, block, file, line) realloc((ptr), (size))
    #define _recalloc_dbg(ptr, num, size, block, file, line) _recalloc((ptr), (num), (size))
    #define _expand_dbg(ptr, newSize, block, file, line) _expand((ptr), (newSize))
    #define _msize_dbg(ptr, block) _msize(ptr)
    #define _strdup_dbg(str, block, file, line) _strdup(str)
    #define _wcsdup_dbg(str, block, file, line) _wcsdup(str)
    #define _mbsdup_dbg(str, block, file, line) _mbsdup(str)
    #define _aligned_malloc_dbg(size, alignment, file, line) _aligned_malloc((size), (alignment))
    #define _aligned_msize_dbg(ptr, alignment, offset) _aligned_msize((ptr), (alignment), (offset))
    #define _aligned_offset_malloc_dbg(size, alignment, offset, file, line) \
        _aligned_offset_malloc((size), (alignment), (offset))
    #define _aligned_offset_realloc_dbg(ptr, size, alignment, offset, file, line) \
        _aligned_offset_realloc((ptr), (size), (alignment), (offset))
    #if 0
        #define _aligned_offset_recalloc_dbg(size, alignment, offset, file, line) \
            _aligned_offset_recalloc((ptr), (num), (size), (alignment), (offset))
    #endif
    #define _aligned_realloc_dbg(ptr, size, alignment, file, line) \
        _aligned_realloc((ptr), (size), (alignment))
    #define _aligned_recalloc_dbg(ptr, num, size, alignment, file, line) \
        _aligned_recalloc((ptr), (num), (size), (alignment))
    #define _aligned_free_dbg(ptr) _aligned_free(ptr)
    #define _malloca_dbg(size, block, file, line) _malloca(size)
    #define _freea_dbg(ptr, block) _freea(ptr)
    #define _tempnam_dbg(dir, prefix, block, file, line) _tempnam((dir), (prefix))
    #define _wtempnam_dbg(dir, prefix, block, file, line) _wtempnam((dir), (prefix))
    #define _dupenv_s_dbg(pptr, num, var, block, file, line) _dupenv_s((pptr), (num), (var))
    #define _wdupenv_s_dbg(pptr, num, var, block, file, line) _wdupenv_s((pptr), (num), (var))
    #define _fullpath_dbg(abspath, relpath, maxlen, block, file, line) \
        _fullpath((abspath), (relpath), (maxlen))
    #define _wfullpath_dbg(abspath, relpath, maxlen, block, file, line) \
        _wfullpath((abspath), (relpath), (maxlen))
    #define _getcwd_dbg(buffer, maxlen, block, file, line) _getcwd((buffer), (maxlen))
    #define _wgetcwd_dbg(buffer, maxlen, block, file, line) _wgetcwd((buffer), (maxlen))
    #define _getdcwd_dbg(drive, buffer, maxlen, block, file, line) \
        _getdcwd((drive), (buffer), (maxlen))
    #define _wgetdcwd_dbg(drive, buffer, maxlen, block, file, line) \
        _wgetdcwd((drive), (buffer), (maxlen))
    #if 0
        #define _getdcwd_lk_dbg(drive, buffer, maxlen, block, file, line) \
            _getdcwd_nolock((drive), (buffer), (maxlen))
        #define _wgetdcwd_lk_dbg(drive, buffer, maxlen, block, file, line) \
            _wgetdcwd_nolock((drive), (buffer), (maxlen))
    #endif
#else /* def _DEBUG */
    #ifdef _CRTDBG_MAP_ALLOC
        #define malloc(size)        _malloc_dbg((size), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define calloc(num, size)   _calloc_dbg((num), (size), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define free(ptr)           _free_dbg((ptr), _NORMAL_BLOCK)
        #define realloc(ptr, size)  _realloc_dbg((ptr), (size), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _recalloc(ptr, num, size)   _recalloc_dbg((ptr), (num), (size), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _expand(ptr, newSize)       _expand_dbg((ptr), (newSize), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _msize(ptr)                 _msize_dbg((ptr), _NORMAL_BLOCK)
        #define _strdup(str) _strdup_dbg((str), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wcsdup(str) _wcsdup_dbg((str), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _mbsdup(str) _mbsdup_dbg((str), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _aligned_malloc(size, alignment)       _aligned_malloc_dbg((size), (alignment), __FILE__, __LINE__)
        #define _aligned_msize(ptr, alignment, offset) _aligned_msize_dbg((ptr), (alignment), (offset))
        #define _aligned_offset_malloc(size, alignment, offset) \
            _aligned_offset_malloc_dbg((size), (alignment), (offset), __FILE__, __LINE__)
        #define _aligned_offset_realloc(ptr, size, alignment, offset) \
            _aligned_offset_realloc_dbg((ptr), (size), (alignment), (offset), __FILE__, __LINE__)
        #if 0
            #define _aligned_offset_recalloc(ptr, num, size, alignment, offset) \
                _aligned_offset_recalloc_dbg((size), (alignment), (offset), __FILE__, __LINE__)
        #endif
        #define _aligned_realloc(ptr, size, alignment) \
            _aligned_realloc_dbg((ptr), (size), (alignment), __FILE__, __LINE__)
        #define _aligned_recalloc(ptr, num, size, alignment) \
            _aligned_recalloc_dbg((ptr), (num), (size), (alignment), __FILE__, __LINE__)
        #define _aligned_free(ptr)      _aligned_free_dbg(ptr) 
        #define _malloca(size)          _malloca_dbg((size), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _freea(ptr)             _freea_dbg((ptr), _NORMAL_BLOCK)
        #define _tempnam(dir, prefix)   _tempnam_dbg((dir), (prefix), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wtempnam(dir, prefix)  _wtempnam_dbg((dir), (prefix), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _dupenv_s(pptr, num, var)   _dupenv_s_dbg((pptr), (num), (var), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wdupenv_s(pptr, num, var)  _wdupenv_s_dbg((pptr), (num), (var), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _fullpath(abspath, relpath, maxlen) \
            _fullpath_dbg((abspath), (relpath), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wfullpath(abspath, relpath, maxlen) \
            _wfullpath_dbg((abspath), (relpath), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _getcwd(buffer, maxlen)     _getcwd_dbg((buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wgetcwd(buffer, maxlen)    _wgetcwd_dbg((buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _getdcwd(drive, buffer, maxlen) \
            _getdcwd_dbg((drive), (buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #define _wgetdcwd(drive, buffer, maxlen) \
            _wgetdcwd_dbg((drive), (buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #if 0
            #define _getdcwd_nolock(drive, buffer, maxlen) \
                _getdcwd_lk_dbg((drive), (buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
            #define _wgetdcwd_nolock(drive, buffer, maxlen) \
                _wgetdcwd_lk_dbg((drive), (buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #endif
        #if defined(_CRT_INTERNAL_NONSTDC_NAMES) && _CRT_INTERNAL_NONSTDC_NAMES
            #define strdup(str)             _strdup_dbg((str), _NORMAL_BLOCK, __FILE__, __LINE__)
            #define wcsdup(str)             _wcsdup_dbg((str), _NORMAL_BLOCK, __FILE__, __LINE__)
            #define tempnam(dir, prefix)    _tempnam_dbg((dir), (prefix), _NORMAL_BLOCK, __FILE__, __LINE__)
            #define getcwd(buffer, maxlen)  _getcwd_dbg((buffer), (maxlen), _NORMAL_BLOCK, __FILE__, __LINE__)
        #endif
    #endif /* def _CRTDBG_MAP_ALLOC */

    MZCRTIMP void *__cdecl _malloc_dbg(size_t size, int blockType, const char *file, int line);
    MZCRTIMP void *__cdecl _calloc_dbg(size_t num, size_t size, int blockType, const char *file, int line);
    MZCRTIMP void __cdecl _free_dbg(void *ptr, int blockType);
    MZCRTIMP void *__cdecl _realloc_dbg(void *ptr, size_t size, int blockType, const char *file, int line);
    #if 0
        MZCRTIMP void * __cdecl _recalloc_dbg(void *ptr, size_t num, size_t size, int blockType,
                                              const char *file, int line);
    #endif
    MZCRTIMP void *__cdecl _expand_dbg(void *ptr, size_t new_size, int blockType, const char *file, int line);
    MZCRTIMP size_t __cdecl _msize_dbg(void *ptr, int blockType);
    MZCRTIMP char *__cdecl _strdup_dbg(const char *str, int blockType, const char *file, int line);
    MZCRTIMP wchar_t *__cdecl _wcsdup_dbg(const wchar_t *str, int blockType, const char *file, int line);
    MZCRTIMP unsigned char *__cdecl _mbsdup_dbg(const unsigned char *str, int blockType, const char *file, int line);
    MZCRTIMP void *__cdecl _aligned_malloc_dbg(size_t size, size_t alignment, const char *file, int line);
    MZCRTIMP size_t __cdecl _aligned_msize_dbg(void *ptr, size_t alignment, size_t offset);
    MZCRTIMP void *__cdecl _aligned_offset_malloc_dbg(size_t size, size_t alignment, size_t offset,
                                                      const char *file, int line);
    MZCRTIMP void *__cdecl _aligned_offset_realloc_dbg(void *ptr, size_t size, size_t alignment,
                                                       size_t offset, const char *file, int line);
    #if 0
        MZCRTIMP void *__cdecl _aligned_offset_recalloc_dbg(void *ptr, size_t num, size_t size,
                                                            size_t alignment, size_t offset,
                                                            const char *file, int line);
    #endif
    MZCRTIMP void *__cdecl _aligned_realloc_dbg(void *ptr, size_t size, size_t alignment,
                                                const char *file, int line);
    #if 0
        MZCRTIMP void *__cdecl _aligned_recalloc_dbg(void *ptr, size_t num, size_t size, size_t alignment,
                                                     const char *file, int line);
    #endif
    MZCRTIMP void __cdecl _aligned_free_dbg(void *ptr);

    #define _malloca_dbg(s, t, f, l) _malloc_dbg(s, t, f, l)
    #define _freea_dbg(p, t)         _free_dbg(p, t)

    MZCRTIMP char *__cdecl _tempnam_dbg(const char *dir, const char *prefix, int blockType,
                                        const char *file, int line);
    MZCRTIMP wchar_t *__cdecl _wtempnam_dbg(const wchar_t *dir, const wchar_t *prefix, int blockType,
                                            const char *file, int line);
    MZCRTIMP errno_t __cdecl _dupenv_s_dbg(char** pptr, size_t* num, const char *var, int blockType,
                                           const char * file, int line);
    MZCRTIMP errno_t __cdecl _wdupenv_s_dbg(wchar_t** pptr, size_t* num, const wchar_t *var,
                                            int blockType, const char *file, int line);
    MZCRTIMP char *__cdecl _fullpath_dbg(char *abspath, const char *relpath, size_t maxlen, int blockType,
                                         const char *file, int line);
    MZCRTIMP wchar_t *__cdecl _wfullpath_dbg(wchar_t *abspath, const wchar_t *relpath, size_t maxlen,
                                             int blockType, const char *file, int line);
    MZCRTIMP char *__cdecl _getcwd_dbg(char *buffer, int maxlen, int blockType, const char *file, int line);
    MZCRTIMP wchar_t *__cdecl _wgetcwd_dbg(wchar_t *buffer, int maxlen, int blockType, const char *file, int line);
    MZCRTIMP char *__cdecl _getdcwd_dbg(int drive, char *buffer, int maxlen, int blockType,
                                        const char *file, int line);
    MZCRTIMP wchar_t *__cdecl _wgetdcwd_dbg(int drive, wchar_t *buffer, int maxlen, int blockType,
                                            const char *file, int line);
    char *__cdecl _getdcwd_lk_dbg(int drive, char *buffer, int maxlen, int blockType, const char *file, int line);
    wchar_t *__cdecl _wgetdcwd_lk_dbg(int drive, wchar_t *buffer, int maxlen, int blockType,
                                      const char *file, int line);

    #if defined(__cplusplus) && defined(_CRTDBG_MAP_ALLOC)
        namespace std
        {
            using ::_malloc_dbg;
            using ::_calloc_dbg;
            using ::_realloc_dbg;
            using ::_free_dbg;
        }
    #endif
#endif /* def _DEBUG */

/* --------------------------------------------
 * Debug reporting
 */

#ifndef _DEBUG
    #define _CrtSetDebugFillThreshold(t)        ((size_t)0)
    #define _CrtSetReportFile(t, f)             ((_HFILE)0)
    #define _CrtSetReportMode(t, f)             ((int)0)
    #define _CrtGetReportHook()                 ((_CRT_REPORT_HOOK)0)
    #define _CrtSetReportHook(f)                ((_CRT_REPORT_HOOK)0)
    #define _CrtSetReportHook2(t, f)            ((int)0)
    #define _CrtSetReportHookW2(t, f)           ((int)0)
#else /* def _DEBUG */
    extern long _crtAssertBusy;
    MZCRTIMP int __cdecl _CrtDbgReport(int reportType, const char *filename, int line,
                                       const char *moduleName, const char *format, ...);
    MZCRTIMP int __cdecl _CrtDbgReportW(int reportType, const wchar_t *filename, int line,
                                        const wchar_t *moduleName, const wchar_t *format, ...);

    MZCRTIMP size_t __cdecl _CrtGetDebugFillThreshold(void);
    MZCRTIMP size_t __cdecl _CrtSetDebugFillThreshold(size_t newThreshold);
    MZCRTIMP _HFILE __cdecl _CrtSetReportFile(int reportType, _HFILE reportFile);
    MZCRTIMP int __cdecl _CrtSetReportMode(int reportType, int reportMode);
    MZCRTIMP _CRT_REPORT_HOOK __cdecl _CrtGetReportHook(void);
    MZCRTIMP _CRT_REPORT_HOOK __cdecl _CrtSetReportHook(_CRT_REPORT_HOOK fnHook);
    MZCRTIMP int __cdecl _CrtSetReportHook2(int mode, _CRT_REPORT_HOOK fnHook);
    MZCRTIMP int __cdecl _CrtSetReportHookW2(int mode, _CRT_REPORT_HOOKW fnHook);
#endif /* def _DEBUG */

/* --------------------------------------------
 * Assertions
 */
#ifndef _DEBUG
    #define _CrtDbgBreak() ((void)0)

    #ifndef _ASSERT_EXPR
        #define _ASSERT_EXPR(exp, msg) ((void)0)
    #endif
    #ifndef _ASSERT
        #define _ASSERT(exp) ((void)0)
    #endif
    #ifndef _ASSERTE
        #define _ASSERTE(exp) ((void)0)
    #endif

    #define _RPT0(rptno, msg)
    #define _RPTN(rptno, msg, ...)

    #define _RPTW0(rptno, msg)
    #define _RPTWN(rptno, msg, ...)

    #define _RPTF0(rptno, msg)
    #define _RPTFN(rptno, msg, ...)

    #define _RPTFW0(rptno, msg)
    #define _RPTFWN(rptno, msg, ...)
#else   /* def _DEBUG */
    #define _CrtDbgBreak() __debugbreak()

    #ifndef _ASSERT_EXPR
        #define _ASSERT_EXPR(exp, msg)
            (void)((!!(exp)) || \
                   (1 != _CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, NULL, "%s", msg)) || \
                   (_CrtDbgBreak(), 0))
    #endif
    #ifndef _ASSERT
        #define _ASSERT(exp) _ASSERT_EXPR((exp), NULL)
    #endif
    #ifndef _ASSERTE
        #define _ASSERTE(exp) _ASSERT_EXPR((exp), _CRT_WIDE(#exp))
    #endif

    #define _RPT_BASE(...)   (void)((1 != _CrtDbgReport (__VA_ARGS__)) || (_CrtDbgBreak(), 0))
    #define _RPT_BASE_W(...) (void)((1 != _CrtDbgReportW(__VA_ARGS__)) || (_CrtDbgBreak(), 0))

    #define _RPT0(rptno, msg)      _RPT_BASE(rptno, NULL, 0, NULL, "%s", msg)
    #define _RPTN(rptno, msg, ...) _RPT_BASE(rptno, NULL, 0, NULL, msg, __VA_ARGS__)

    #define _RPTW0(rptno, msg)      _RPT_BASE_W(rptno, NULL, 0, NULL, L"%ls", msg)
    #define _RPTWN(rptno, msg, ...) _RPT_BASE_W(rptno, NULL, 0, NULL, msg, __VA_ARGS__)

    #define _RPTF0(rptno, msg)      _RPT_BASE(rptno, __FILE__, __LINE__, NULL, "%s", msg)
    #define _RPTFN(rptno, msg, ...) _RPT_BASE(rptno, __FILE__, __LINE__, NULL, msg, __VA_ARGS__)

    #define _RPTFW0(rptno, msg)      _RPT_BASE_W(rptno, _CRT_WIDE(__FILE__), __LINE__, NULL, L"%ls", msg)
    #define _RPTFWN(rptno, msg, ...) _RPT_BASE_W(rptno, _CRT_WIDE(__FILE__), __LINE__, NULL, msg, __VA_ARGS__)
#endif /* def _DEBUG */

#ifndef _ASSERT_BASE
    #define _ASSERT_BASE _ASSERT_EXPR
#endif

#define _RPT1 _RPTN
#define _RPT2 _RPTN
#define _RPT3 _RPTN
#define _RPT4 _RPTN
#define _RPT5 _RPTN

#define _RPTW1 _RPTWN
#define _RPTW2 _RPTWN
#define _RPTW3 _RPTWN
#define _RPTW4 _RPTWN
#define _RPTW5 _RPTWN

#define _RPTF1 _RPTFN
#define _RPTF2 _RPTFN
#define _RPTF3 _RPTFN
#define _RPTF4 _RPTFN
#define _RPTF5 _RPTFN

#define _RPTFW1 _RPTFWN
#define _RPTFW2 _RPTFWN
#define _RPTFW3 _RPTFWN
#define _RPTFW4 _RPTFWN
#define _RPTFW5 _RPTFWN

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _INC_CRTDBG */
