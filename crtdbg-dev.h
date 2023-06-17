#pragma once

struct _CrtMemBlockHeader;

typedef struct _CrtMemBlockHeader
{
    struct _CrtMemBlockHeader* _block_header_next;
    struct _CrtMemBlockHeader* _block_header_prev;
    const char *_file_name;
    int _line_number;
    int _block_use;
    size_t _data_size;
    long _request_number;
    unsigned char _gap[4];
} _CrtMemBlockHeader;

#ifdef __cplusplus
extern "C" {
#endif

void DebugVPrintfA(const char *fmt, va_list va);
void DebugVPrintfW(const wchar_t *fmt, va_list va);
void DebugPrintfA(const char *fmt, ...);
void DebugPrintfW(const wchar_t *fmt, ...);

#ifdef __cplusplus
} // extern "C"
#endif
