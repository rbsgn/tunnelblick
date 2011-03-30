/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010 Brian Raderman <brian@irregularexpression.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "common_osx.h"

void printCFString(CFStringRef str)
{
	CFIndex bufferLength = CFStringGetLength(str) + 1;
	char *pBuffer = (char*)malloc(sizeof(char) * bufferLength);
	CFStringGetCString(str, pBuffer, bufferLength, kCFStringEncodingUTF8);
	printf("%s", pBuffer);
	free(pBuffer);
}

char* cfstringToCstr(CFStringRef str)
{
	CFIndex bufferLength = CFStringGetLength(str) + 1;
	char *pBuffer = (char*)malloc(sizeof(char) * bufferLength);
	CFStringGetCString(str, pBuffer, bufferLength, kCFStringEncodingUTF8);
	return pBuffer;
}

void appendHexChar(CFMutableStringRef str, unsigned char halfByte)
{
	if (halfByte < 10)
		CFStringAppendFormat (str, NULL, CFSTR("%d"), halfByte);
	
	switch(halfByte)
	{
		case 10:
			CFStringAppendCString(str, "A", kCFStringEncodingUTF8);
			break;
		case 11:
			CFStringAppendCString(str, "B", kCFStringEncodingUTF8);
			break;
		case 12:
			CFStringAppendCString(str, "C", kCFStringEncodingUTF8);
			break;
		case 13:
			CFStringAppendCString(str, "D", kCFStringEncodingUTF8);
			break;
		case 14:
			CFStringAppendCString(str, "E", kCFStringEncodingUTF8);
			break;
		case 15:
			CFStringAppendCString(str, "F", kCFStringEncodingUTF8);
			break;
	}
}

CFStringRef createHexString(unsigned char *pData, int length)
{
	unsigned char byte, low, high;
	int i;
	CFMutableStringRef str = CFStringCreateMutable(NULL, 0);
	
	for(i = 0;i < length;i++)
	{
		byte = pData[i];
		low = byte & 0x0F;
		high = (byte >> 4);
		
		appendHexChar(str, high);
		appendHexChar(str, low);
		
		if (i != (length - 1))
			CFStringAppendCString(str, " ", kCFStringEncodingUTF8);
	}
	
	return str;
}

void printHex(unsigned char *pData, int length)
{
	CFStringRef hexStr = createHexString(pData, length);
	printCFString(hexStr);
	CFRelease(hexStr);
}