#ifndef OUT_DEBUG_HPP
#define OUT_DEBUG_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <string>
#include <windows.h>
#include <Strsafe.h>
#include <ctype.h>
#include <direct.h>
using namespace std;

#pragma warning(push)  
#pragma warning(disable:4995) 
#pragma warning(disable:4996) 

namespace xzh
{
	class out_msg_nil
	{
	public:
		static void showmsg(string l_out_msg)
		{

		}
	};
	
	class out_msg_dbg
	{
	public:
		static void showmsg(string l_out_msg, bool isflush = false)
		{
			OutputDebugStringA(string(string("[007] [001]") + l_out_msg.c_str() + "\n").c_str() );
		}
	};
	
	
	template <class s = out_msg_dbg>
	class debughelp_impl
	{
		typedef s out_msg_base; 
	public:
		static void safe_debugstr(int max_size, const char* lpformat, ...)
		{
			do 
			{
				string l_out_debug;
				l_out_debug.resize(max_size + 1);
				va_list l_va_list;
				va_start(l_va_list, lpformat);
				StringCchVPrintfA((char*)l_out_debug.c_str(), max_size + 1, lpformat, l_va_list);
				va_end(l_va_list);
				l_out_debug.resize(strlen(l_out_debug.c_str()));
	
				out_msg_base::showmsg(l_out_debug);
	
			} while (false);
		}

		static void safe_log(void *data, long len, const char* lpfile_path = "")
		{
			do 
			{
				FILE* file_ = NULL;
				
				do 
				{
					string strfile_path;
					strfile_path.resize(260);

					if (strlen(lpfile_path) == 0)
					{
						sprintf((char*)strfile_path.c_str(), "%08x.log", GetTickCount());
					}
					else
					{
						sprintf((char*)strfile_path.c_str(), lpfile_path);
					}

					file_ = fopen(strfile_path.c_str(), "ab+");
					if (file_ == NULL)
					{
						break;
					}

					size_t iwrite_len = fwrite(data, sizeof(unsigned char), len, file_);
					assert(iwrite_len == len);

				} while (false);

				if (file_ != NULL)
				{
					fclose(file_);
				}

			} while (false);
		}
		
		static void hexdump(void *data, long  len)
		{
			char szBuf[100];
			long lIndent = 1;
			long lOutLen, lIndex, lIndex2, lOutLen2;
			long lRelPos;
			struct { char *pData; unsigned long len; } buf;
			unsigned char *pTmp,ucTmp;
			unsigned char *pAddress = (unsigned char *)data;

			buf.pData   = (char *)pAddress;
			buf.len   = len;

			while (buf.len > 0)
			{
				pTmp     = (unsigned char *)buf.pData;
				lOutLen  = (int)buf.len;
				if (lOutLen > 16)
					lOutLen = 16;

				// create a 64-character formatted output line:
				sprintf(szBuf, " >                            "
					"                      "
					"    %08lX", pTmp-pAddress);
				lOutLen2 = lOutLen;

				for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
					lOutLen2;
					lOutLen2--, lIndex += 2, lIndex2++
					)
				{
					ucTmp = *pTmp++;

					sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
					if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
					szBuf[lIndex2] = ucTmp;

					if (!(++lRelPos & 3))     // extra blank after 4 bytes
					{  lIndex++; szBuf[lIndex+2] = ' '; }
				}

				if (!(lRelPos & 3)) lIndex--;

				szBuf[lIndex  ]   = '<';
				szBuf[lIndex+1]   = ' ';

				//printf("%s\n", szBuf);
				out_msg_base::showmsg(szBuf);

				buf.pData   += lOutLen;
				buf.len   -= lOutLen;
			}
		}
	};
	
	#ifdef _DEBUG
	typedef debughelp_impl<> debughelp;
	#else
	typedef debughelp_impl<> debughelp;
	#endif
}
#pragma warning(pop) 
#endif