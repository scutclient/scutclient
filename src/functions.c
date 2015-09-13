#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
extern uint8_t BroadcastAddr[6]; // 广播MAC地址
extern uint8_t MultcastAddr[6]; // 多播MAC地址
char ipaddrinfo[16]={0};
extern uint8_t	ip[4];	// ip address
extern uint8_t mask[4];
extern uint8_t gateway[4];
extern uint8_t dns[4];
extern uint8_t	MAC[6];
void GetInfoFromDevice();
void check(unsigned char *buf);
unsigned char encode(unsigned char base);
void TransMAC( char *str );
void TransIP( char *str ,uint8_t iphex[4]);
void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen);
void FillClientVersionArea(uint8_t area[20]);
void FillWindowsVersionArea(uint8_t area[20]);
void FillBase64Area(char area[]);
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[]);
uint8_t	EthHeader[14]={0}; // ethernet header
const char H3C_VERSION[]="EN V2.40-0335"; // 华为客户端版本号
const char H3C_KEY[]      ="HuaWei3COM1X";  // H3C的固定密钥





uint8_t checksum[23]={
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

uint8_t netinfo[46]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
,0x00,0x33,0x2e,0x35,0x2e,0x30,0x35,0x2e,0x30,0x35,0x31,0x39,0x66,0x6b};

extern size_t userlen,iplen;
extern char *UserName;
extern char *Password;
extern char *DeviceName;

void GetInfoFromDevice()
{
	FILE   *stream;
	char    buf[100]={0}; 
	int	count = 0;
	char ipaddr[16]={0};
	char maskaddr[16]={0};
	char gatewayaddr[16]={0};
	char dnsaddr[16]={0};
	userlen=strlen(UserName);
	stream = popen( "uci get network.wan.ipaddr", "r" );
//stream = popen( "echo 192.168.1.100", "r" );
	if(stream == NULL)
		printf("Command error : uci get network.wan.ipaddr not found , this command is used on OpenWRT");
	else
	{
		count = fread( buf, sizeof(char), sizeof(buf), stream); 
		memcpy(ipaddr, buf , count-1);
		memcpy(ipaddrinfo, buf , count-1);
		iplen=strlen(ipaddr);
		printf("Your ip : %s \n",ipaddr);
	}
	pclose( stream ); 

	stream = popen( "uci get network.wan.netmask", "r" );
//stream = popen( "echo 255.255.255.0", "r" );
	if(stream == NULL)
	printf("Command error : uci get network.wan.netmask not found , this command is used on OpenWRT");
	else
	{
		count = fread( buf, sizeof(char), sizeof(buf), stream); 
		memcpy(maskaddr, buf , count-1);
		printf("Your mask : %s \n",maskaddr);
	}
		pclose( stream ); 

	stream = popen( "uci get network.wan.gateway", "r" );
//stream = popen( "echo 192.168.1.1", "r" );
	if(stream == NULL)
		printf("Command error : uci get network.wan.gateway not found , this command is used on OpenWRT");
	else
	{
		count = fread( buf, sizeof(char), sizeof(buf), stream); 
		memcpy(gatewayaddr, buf , count-1);
		printf("Your gateway : %s \n",gatewayaddr);
	}
	pclose( stream ); 

	stream = popen( "uci get network.wan.dns | cut -d ' ' -f 1", "r" );
//stream = popen( "echo 192.168.1.1", "r" );
	if(stream == NULL)
		printf("Command error : uci get network.wan.dns | cut -d ' ' -f 1 not found , this command is used on OpenWRT");
	else
	{
		count = fread( buf, sizeof(char), sizeof(buf), stream);
		memcpy(dnsaddr, buf , count-1);
		printf("Your DNS : %s \n",dnsaddr);
	}
	pclose( stream ); 

	stream = popen( "uci get network.wan.macaddr", "r" );
//stream = popen( "echo 00:0c:29:e3:03:03", "r" );
	if(stream == NULL)
		printf("Command error : uci get network.wan.macaddr not found , this command is used on OpenWRT");
	else
	{
		count = fread( buf, sizeof(char), sizeof(buf), stream);
//		sscanf(buf,"%02X:%02X:%02X:%02X:%02:%02X\n",&MAC[0],&MAC[1],&MAC[2],&MAC[3],&MAC[4],&MAC[5]);
		TransMAC(buf);
		printf("Comfirmed your MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	}
	pclose( stream ); 
	memcpy(EthHeader+0, MultcastAddr, 6);
	memcpy(EthHeader+6, MAC, 6);
	EthHeader[12] = 0x88;
	EthHeader[13] = 0x8e;

	//Init YoungInfo




	unsigned char checkinfo[23]={0x00};  //这里赋初始值
	
	checkinfo[0]=0x00;
	checkinfo[1]=0x00;
	checkinfo[2]=0x13;
	checkinfo[3]=0x11;
	checkinfo[4]=0x00;



	TransIP(ipaddr,ip);
	memcpy(checkinfo+5, ip, 4);
	memcpy(netinfo+1, ip, 4);

	TransIP(maskaddr,mask);
	memcpy(checkinfo+9, mask, 4);
	memcpy(netinfo+5, mask, 4);

	TransIP(gatewayaddr,gateway);
	memcpy(checkinfo+13, gateway, 4);
	memcpy(netinfo+9, gateway, 4);

	TransIP(dnsaddr,dns);
	memcpy(checkinfo+17, dns, 4);
	memset(netinfo+13, 0x00, 4);


	netinfo[0]=0x00;

	check(checkinfo);
	uint8_t	msgbuf[128];
	memcpy(msgbuf,UserName,userlen);
	MD5Calc(msgbuf, userlen, netinfo+17);

	return;
}

void check(unsigned char *buf)
{
	unsigned char table[] =
	{
	0x00,0x00,0x21,0x10,0x42,0x20,0x63,0x30,0x84,0x40,0xA5,0x50,0xC6,0x60,0xE7,0x70,
			0x08,0x81,0x29,0x91,0x4A,0xA1,0x6B,0xB1,0x8C,0xC1,0xAD,0xD1,0xCE,0xE1,0xEF,0xF1,
			0x31,0x12,0x10,0x02,0x73,0x32,0x52,0x22,0xB5,0x52,0x94,0x42,0xF7,0x72,0xD6,0x62,
			0x39,0x93,0x18,0x83,0x7B,0xB3,0x5A,0xA3,0xBD,0xD3,0x9C,0xC3,0xFF,0xF3,0xDE,0xE3,
			0x62,0x24,0x43,0x34,0x20,0x04,0x01,0x14,0xE6,0x64,0xC7,0x74,0xA4,0x44,0x85,0x54,
			0x6A,0xA5,0x4B,0xB5,0x28,0x85,0x09,0x95,0xEE,0xE5,0xCF,0xF5,0xAC,0xC5,0x8D,0xD5,
			0x53,0x36,0x72,0x26,0x11,0x16,0x30,0x06,0xD7,0x76,0xF6,0x66,0x95,0x56,0xB4,0x46,
			0x5B,0xB7,0x7A,0xA7,0x19,0x97,0x38,0x87,0xDF,0xF7,0xFE,0xE7,0x9D,0xD7,0xBC,0xC7,
			0xC4,0x48,0xE5,0x58,0x86,0x68,0xA7,0x78,0x40,0x08,0x61,0x18,0x02,0x28,0x23,0x38,
			0xCC,0xC9,0xED,0xD9,0x8E,0xE9,0xAF,0xF9,0x48,0x89,0x69,0x99,0x0A,0xA9,0x2B,0xB9,
			0xF5,0x5A,0xD4,0x4A,0xB7,0x7A,0x96,0x6A,0x71,0x1A,0x50,0x0A,0x33,0x3A,0x12,0x2A,
			0xFD,0xDB,0xDC,0xCB,0xBF,0xFB,0x9E,0xEB,0x79,0x9B,0x58,0x8B,0x3B,0xBB,0x1A,0xAB,
			0xA6,0x6C,0x87,0x7C,0xE4,0x4C,0xC5,0x5C,0x22,0x2C,0x03,0x3C,0x60,0x0C,0x41,0x1C,
			0xAE,0xED,0x8F,0xFD,0xEC,0xCD,0xCD,0xDD,0x2A,0xAD,0x0B,0xBD,0x68,0x8D,0x49,0x9D,
			0x97,0x7E,0xB6,0x6E,0xD5,0x5E,0xF4,0x4E,0x13,0x3E,0x32,0x2E,0x51,0x1E,0x70,0x0E,
			0x9F,0xFF,0xBE,0xEF,0xDD,0xDF,0xFC,0xCF,0x1B,0xBF,0x3A,0xAF,0x59,0x9F,0x78,0x8F,
			0x88,0x91,0xA9,0x81,0xCA,0xB1,0xEB,0xA1,0x0C,0xD1,0x2D,0xC1,0x4E,0xF1,0x6F,0xE1,
			0x80,0x10,0xA1,0x00,0xC2,0x30,0xE3,0x20,0x04,0x50,0x25,0x40,0x46,0x70,0x67,0x60,
			0xB9,0x83,0x98,0x93,0xFB,0xA3,0xDA,0xB3,0x3D,0xC3,0x1C,0xD3,0x7F,0xE3,0x5E,0xF3,
			0xB1,0x02,0x90,0x12,0xF3,0x22,0xD2,0x32,0x35,0x42,0x14,0x52,0x77,0x62,0x56,0x72,
			0xEA,0xB5,0xCB,0xA5,0xA8,0x95,0x89,0x85,0x6E,0xF5,0x4F,0xE5,0x2C,0xD5,0x0D,0xC5,
			0xE2,0x34,0xC3,0x24,0xA0,0x14,0x81,0x04,0x66,0x74,0x47,0x64,0x24,0x54,0x05,0x44,
			0xDB,0xA7,0xFA,0xB7,0x99,0x87,0xB8,0x97,0x5F,0xE7,0x7E,0xF7,0x1D,0xC7,0x3C,0xD7,
			0xD3,0x26,0xF2,0x36,0x91,0x06,0xB0,0x16,0x57,0x66,0x76,0x76,0x15,0x46,0x34,0x56,
			0x4C,0xD9,0x6D,0xC9,0x0E,0xF9,0x2F,0xE9,0xC8,0x99,0xE9,0x89,0x8A,0xB9,0xAB,0xA9,
			0x44,0x58,0x65,0x48,0x06,0x78,0x27,0x68,0xC0,0x18,0xE1,0x08,0x82,0x38,0xA3,0x28,
			0x7D,0xCB,0x5C,0xDB,0x3F,0xEB,0x1E,0xFB,0xF9,0x8B,0xD8,0x9B,0xBB,0xAB,0x9A,0xBB,
			0x75,0x4A,0x54,0x5A,0x37,0x6A,0x16,0x7A,0xF1,0x0A,0xD0,0x1A,0xB3,0x2A,0x92,0x3A,
			0x2E,0xFD,0x0F,0xED,0x6C,0xDD,0x4D,0xCD,0xAA,0xBD,0x8B,0xAD,0xE8,0x9D,0xC9,0x8D,
			0x26,0x7C,0x07,0x6C,0x64,0x5C,0x45,0x4C,0xA2,0x3C,0x83,0x2C,0xE0,0x1C,0xC1,0x0C,
			0x1F,0xEF,0x3E,0xFF,0x5D,0xCF,0x7C,0xDF,0x9B,0xAF,0xBA,0xBF,0xD9,0x8F,0xF8,0x9F,
			0x17,0x6E,0x36,0x7E,0x55,0x4E,0x74,0x5E,0x93,0x2E,0xB2,0x3E,0xD1,0x0E,0xF0,0x1E
	};
	unsigned char *check = buf + 0x15;
	int i, index;
	for (i=0; i<0x15; i++)
	{
		index = check[0] ^ buf[i];
		check[0] = check[1] ^ table[index*2+1];
		check[1] = table[index*2];
	}
	for (i=0; i<0x17; i++)
		buf[i] = encode(buf[i]);
	memcpy(checksum, buf, 23);
				
}



unsigned char encode(unsigned char base)   
{
        unsigned char result = 0;
        int i;
        for (i=0; i<8; i++)
        {
                result <<= 1;
                result |= base&0x01;
                base >>= 1;
        }
        return ~result;
}

void TransMAC( char *str ) 
{
	char *p;
	int count=0;
	p = strtok(str, ":");
   	 if(p != NULL)
	{   
		MAC[count++] = strtoul(p,0,16);
		while(1)
		{   
			p = strtok(NULL, ":");
			if(p == NULL)
				break;
			else
				MAC[count++] = strtoul(p,0,16);
           
		}
	}
	return;
}

void TransIP( char *str ,uint8_t iphex[4])
{
	char *p;
	int count=0;
	p = strtok(str, ".");
   	 if(p != NULL)
	{   
		iphex[count++] = atol(p);
		while(1)
		{   
			p = strtok(NULL, ".");
			if(p == NULL)
				break;
			else
				iphex[count++] = atol(p);
           
		}
	}
	return;
}


//MD5 function START

// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The original file was copied from sqlite, and was in the public domain.

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifndef WIN32
#include <unistd.h>
#endif
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>

// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MD5_H_
#define BASE_MD5_H_


#define BASE_EXPORT

// MD5 stands for Message Digest algorithm 5.
// MD5 is a robust hash function, designed for cyptography, but often used
// for file checksums.  The code is complex and slow, but has few
// collisions.
// See Also:
//   http://en.wikipedia.org/wiki/MD5

// These functions perform MD5 operations. The simplest call is MD5Sum() to
// generate the MD5 sum of the given data.
//
// You can also compute the MD5 sum of data incrementally by making multiple
// calls to MD5Update():
//   MD5Context ctx; // intermediate MD5 data: do not use
//   MD5Init(&ctx);
//   MD5Update(&ctx, data1, length1);
//   MD5Update(&ctx, data2, length2);
//   ...
//
//   MD5Digest digest; // the result of the computation
//   MD5Final(&digest, &ctx);
//
// You can call MD5DigestToBase16() to generate a string of the digest.

// The output of an MD5 operation.
struct MD5Digest {
  unsigned char a[16];
};

// Used for storing intermediate data during an MD5 computation. Callers
// should not access the data.
typedef char MD5Context[88];

// Computes the MD5 sum of the given data buffer with the given length.
// The given 'digest' structure will be filled with the result data.
BASE_EXPORT void MD5Sum(const void* data, size_t length, struct MD5Digest* digest);

// Initializes the given MD5 context structure for subsequent calls to
// MD5Update().
BASE_EXPORT void MD5Init(MD5Context* context);

// For the given buffer of |data| as a StringPiece, updates the given MD5
// context with the sum of the data. You can call this any number of times
// during the computation, except that MD5Init() must have been called first.
BASE_EXPORT void MD5Update(MD5Context* context, const unsigned char *data, size_t length);    //const StringPiece& data);

// Finalizes the MD5 operation and fills the buffer with the digest.
BASE_EXPORT void MD5Final(struct MD5Digest* digest, MD5Context* context);

BASE_EXPORT void MD5Calc(unsigned char *data, unsigned int len, unsigned char *output);


#endif  // BASE_MD5_H_


typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef uint32_t uint32;

struct Context {
  uint32 buf[4];
  uint32 bits[2];
  unsigned char in[64];
};

/*
 * Note: this code is harmless on little-endian machines.
 */
void byteReverse(unsigned char *buf, unsigned longs) {
        uint32 t;
        do {
                t = (uint32)((unsigned)buf[3]<<8 | buf[2]) << 16 |
                            ((unsigned)buf[1]<<8 | buf[0]);
                *(uint32 *)buf = t;
                buf += 4;
        } while (--longs);
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void MD5Transform(uint32 buf[4], const uint32 in[16]) {
        register uint32 a, b, c, d;

        a = buf[0];
        b = buf[1];
        c = buf[2];
        d = buf[3];

        MD5STEP(F1, a, b, c, d, in[ 0]+0xd76aa478,  7);
        MD5STEP(F1, d, a, b, c, in[ 1]+0xe8c7b756, 12);
        MD5STEP(F1, c, d, a, b, in[ 2]+0x242070db, 17);
        MD5STEP(F1, b, c, d, a, in[ 3]+0xc1bdceee, 22);
        MD5STEP(F1, a, b, c, d, in[ 4]+0xf57c0faf,  7);
        MD5STEP(F1, d, a, b, c, in[ 5]+0x4787c62a, 12);
        MD5STEP(F1, c, d, a, b, in[ 6]+0xa8304613, 17);
        MD5STEP(F1, b, c, d, a, in[ 7]+0xfd469501, 22);
        MD5STEP(F1, a, b, c, d, in[ 8]+0x698098d8,  7);
        MD5STEP(F1, d, a, b, c, in[ 9]+0x8b44f7af, 12);
        MD5STEP(F1, c, d, a, b, in[10]+0xffff5bb1, 17);
        MD5STEP(F1, b, c, d, a, in[11]+0x895cd7be, 22);
        MD5STEP(F1, a, b, c, d, in[12]+0x6b901122,  7);
        MD5STEP(F1, d, a, b, c, in[13]+0xfd987193, 12);
        MD5STEP(F1, c, d, a, b, in[14]+0xa679438e, 17);
        MD5STEP(F1, b, c, d, a, in[15]+0x49b40821, 22);

        MD5STEP(F2, a, b, c, d, in[ 1]+0xf61e2562,  5);
        MD5STEP(F2, d, a, b, c, in[ 6]+0xc040b340,  9);
        MD5STEP(F2, c, d, a, b, in[11]+0x265e5a51, 14);
        MD5STEP(F2, b, c, d, a, in[ 0]+0xe9b6c7aa, 20);
        MD5STEP(F2, a, b, c, d, in[ 5]+0xd62f105d,  5);
        MD5STEP(F2, d, a, b, c, in[10]+0x02441453,  9);
        MD5STEP(F2, c, d, a, b, in[15]+0xd8a1e681, 14);
        MD5STEP(F2, b, c, d, a, in[ 4]+0xe7d3fbc8, 20);
        MD5STEP(F2, a, b, c, d, in[ 9]+0x21e1cde6,  5);
        MD5STEP(F2, d, a, b, c, in[14]+0xc33707d6,  9);
        MD5STEP(F2, c, d, a, b, in[ 3]+0xf4d50d87, 14);
        MD5STEP(F2, b, c, d, a, in[ 8]+0x455a14ed, 20);
        MD5STEP(F2, a, b, c, d, in[13]+0xa9e3e905,  5);
        MD5STEP(F2, d, a, b, c, in[ 2]+0xfcefa3f8,  9);
        MD5STEP(F2, c, d, a, b, in[ 7]+0x676f02d9, 14);
        MD5STEP(F2, b, c, d, a, in[12]+0x8d2a4c8a, 20);

        MD5STEP(F3, a, b, c, d, in[ 5]+0xfffa3942,  4);
        MD5STEP(F3, d, a, b, c, in[ 8]+0x8771f681, 11);
        MD5STEP(F3, c, d, a, b, in[11]+0x6d9d6122, 16);
        MD5STEP(F3, b, c, d, a, in[14]+0xfde5380c, 23);
        MD5STEP(F3, a, b, c, d, in[ 1]+0xa4beea44,  4);
        MD5STEP(F3, d, a, b, c, in[ 4]+0x4bdecfa9, 11);
        MD5STEP(F3, c, d, a, b, in[ 7]+0xf6bb4b60, 16);
        MD5STEP(F3, b, c, d, a, in[10]+0xbebfbc70, 23);
        MD5STEP(F3, a, b, c, d, in[13]+0x289b7ec6,  4);
        MD5STEP(F3, d, a, b, c, in[ 0]+0xeaa127fa, 11);
        MD5STEP(F3, c, d, a, b, in[ 3]+0xd4ef3085, 16);
        MD5STEP(F3, b, c, d, a, in[ 6]+0x04881d05, 23);
        MD5STEP(F3, a, b, c, d, in[ 9]+0xd9d4d039,  4);
        MD5STEP(F3, d, a, b, c, in[12]+0xe6db99e5, 11);
        MD5STEP(F3, c, d, a, b, in[15]+0x1fa27cf8, 16);
        MD5STEP(F3, b, c, d, a, in[ 2]+0xc4ac5665, 23);

        MD5STEP(F4, a, b, c, d, in[ 0]+0xf4292244,  6);
        MD5STEP(F4, d, a, b, c, in[ 7]+0x432aff97, 10);
        MD5STEP(F4, c, d, a, b, in[14]+0xab9423a7, 15);
        MD5STEP(F4, b, c, d, a, in[ 5]+0xfc93a039, 21);
        MD5STEP(F4, a, b, c, d, in[12]+0x655b59c3,  6);
        MD5STEP(F4, d, a, b, c, in[ 3]+0x8f0ccc92, 10);
        MD5STEP(F4, c, d, a, b, in[10]+0xffeff47d, 15);
        MD5STEP(F4, b, c, d, a, in[ 1]+0x85845dd1, 21);
        MD5STEP(F4, a, b, c, d, in[ 8]+0x6fa87e4f,  6);
        MD5STEP(F4, d, a, b, c, in[15]+0xfe2ce6e0, 10);
        MD5STEP(F4, c, d, a, b, in[ 6]+0xa3014314, 15);
        MD5STEP(F4, b, c, d, a, in[13]+0x4e0811a1, 21);
        MD5STEP(F4, a, b, c, d, in[ 4]+0xf7537e82,  6);
        MD5STEP(F4, d, a, b, c, in[11]+0xbd3af235, 10);
        MD5STEP(F4, c, d, a, b, in[ 2]+0x2ad7d2bb, 15);
        MD5STEP(F4, b, c, d, a, in[ 9]+0xeb86d391, 21);

        buf[0] += a;
        buf[1] += b;
        buf[2] += c;
        buf[3] += d;
}


/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5Init(MD5Context* context) {
        struct Context *ctx = (struct Context *)context;
        ctx->buf[0] = 0x67452301;
        ctx->buf[1] = 0xefcdab89;
        ctx->buf[2] = 0x98badcfe;
        ctx->buf[3] = 0x10325476;
        ctx->bits[0] = 0;
        ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5Update(MD5Context* context, const unsigned char *data, size_t length) /*const StringPiece& data)*/
{
        const unsigned char* inbuf = data;   //(const unsigned char*)data.data();
        size_t len = length;    //data.size();
        struct Context *ctx = (struct Context *)context;
        const unsigned char* buf = (const unsigned char*)inbuf;
        uint32 t;

        /* Update bitcount */

        t = ctx->bits[0];
        if ((ctx->bits[0] = t + ((uint32)len << 3)) < t)
                ctx->bits[1]++; /* Carry from low to high */
        ctx->bits[1] += (uint32)(len >> 29);    //static_cast<uint32>(len >> 29);

        t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

        /* Handle any leading odd-sized chunks */

        if (t) {
                unsigned char *p = (unsigned char *)ctx->in + t;

                t = 64-t;
                if (len < t) {
                        memcpy(p, buf, len);
                        return;
                }
                memcpy(p, buf, t);
                byteReverse(ctx->in, 16);
                MD5Transform(ctx->buf, (uint32 *)ctx->in);
                buf += t;
                len -= t;
        }

        /* Process data in 64-byte chunks */

        while (len >= 64) {
                memcpy(ctx->in, buf, 64);
                byteReverse(ctx->in, 16);
                MD5Transform(ctx->buf, (uint32 *)ctx->in);
                buf += 64;
                len -= 64;
        }

        /* Handle any remaining bytes of data. */

        memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(struct MD5Digest* digest, MD5Context* context) {
        struct Context *ctx = (struct Context *)context;
        unsigned count;
        unsigned char *p;

        /* Compute number of bytes mod 64 */
        count = (ctx->bits[0] >> 3) & 0x3F;

        /* Set the first char of padding to 0x80.  This is safe since there is
           always at least one byte free */
        p = ctx->in + count;
        *p++ = 0x80;

        /* Bytes of padding needed to make 64 bytes */
        count = 64 - 1 - count;

        /* Pad out to 56 mod 64 */
        if (count < 8) {
                /* Two lots of padding:  Pad the first block to 64 bytes */
                memset(p, 0, count);
                byteReverse(ctx->in, 16);
                MD5Transform(ctx->buf, (uint32 *)ctx->in);

                /* Now fill the next block with 56 bytes */
                memset(ctx->in, 0, 56);
        } else {
                /* Pad block to 56 bytes */
                memset(p, 0, count-8);
        }
        byteReverse(ctx->in, 14);

        /* Append length in bits and transform */
        ((uint32 *)ctx->in)[ 14 ] = ctx->bits[0];
        ((uint32 *)ctx->in)[ 15 ] = ctx->bits[1];

        MD5Transform(ctx->buf, (uint32 *)ctx->in);
        byteReverse((unsigned char *)ctx->buf, 4);
        memcpy(digest->a, ctx->buf, 16);
        memset(ctx, 0, sizeof(*ctx));    /* In case it's sensitive */
}


void MD5Calc(unsigned char *data, unsigned int len, unsigned char *output)
{
	MD5Context context;
	struct MD5Digest digest;
    
	MD5Init(&context);
	MD5Update(&context, (unsigned char *)data, len);
	MD5Final(&digest, &context);
    
	memcpy(output, digest.a, 16);
}

//MD5 function END


void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int	i,j;

	// 先按正序处理一遍
	for (i=0; i<dlen; i++)
		data[i] ^= key[i%klen];
	// 再按倒序处理第二遍
	for (i=dlen-1,j=0;  j<dlen;  i--,j++)
		data[i] ^= key[j%klen];
}

void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char	 RandomKey[8+1];

	random = (uint32_t) time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);// 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); // （需调整为网络字节序）
	memcpy(area+16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";

	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

void FillBase64Area(char area[])
{
	uint8_t	c1,c2,c3;
	int	i, j;
	uint8_t version[20];
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			   "abcdefghijklmnopqrstuvwxyz"
			   "0123456789+/"; // 标准的Base64字符映射表

	// 首先生成20字节加密过的H3C版本号信息
	FillClientVersionArea(version);

	// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[ (c1&0xfc)>>2                               ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)               ];
		area[j++] = Tbl[               ((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[                                c3&0x3f     ];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[               ((c2&0x0f)<<2)];
	area[27] = '=';
}

void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
	uint8_t	msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’

	int	passlen = strlen(passwd);
	int msglen = 1 + passlen + 16;
	assert(sizeof(msgbuf) >= msglen);

	msgbuf[0] = id;
	memcpy(msgbuf+1,	 passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);

	//(void)MD5(msgbuf, msglen, digest);
	MD5Calc(msgbuf, msglen, digest);
}
