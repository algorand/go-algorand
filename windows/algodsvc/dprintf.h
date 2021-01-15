#ifndef __DPRINTF_H__
#define __DPRINTF_H__

#include <Windows.h>
#include <strsafe.h>

inline void dprintfW(const wchar_t* fmt, ...)
{
	const size_t MAX_MSG = 255;

	va_list args;
	va_start(args, fmt);

	wchar_t msg[MAX_MSG];
	StringCbVPrintfW(msg, MAX_MSG * sizeof(wchar_t), fmt, args);
	OutputDebugStringW(msg);

	va_end(args);
}

inline void dprintfA(const char* fmt, ...)
{
	const size_t MAX_MSG = 255;

	va_list args;
	va_start(args, fmt);

	char msg[MAX_MSG];
	StringCbVPrintfA(msg, MAX_MSG, fmt, args);
	OutputDebugStringA(msg);

	va_end(args);
}

#ifdef _DEBUG
#define _TRACE dprintf(L"At %s line %d",__FUNCTIONW__,__LINE__)
#else
#define _TRACE
#endif

#endif // __DPRINTF_H__