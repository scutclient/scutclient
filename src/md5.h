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

