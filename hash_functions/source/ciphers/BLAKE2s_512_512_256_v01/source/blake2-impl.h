/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
    #if   defined(_MSC_VER)
        #define BLAKE2_INLINE __inline
    #elif defined(__GNUC__)
        #define BLAKE2_INLINE __inline__
    #else
        #define BLAKE2_INLINE
    #endif
#else
    #define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE uint32_t load32( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = ( const uint8_t * )src;
    return (( uint32_t )( p[0] ) <<  0) |
           (( uint32_t )( p[1] ) <<  8) |
           (( uint32_t )( p[2] ) << 16) |
           (( uint32_t )( p[3] ) << 24) ;
#endif
}

static BLAKE2_INLINE void store32( void *dst, uint32_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = ( uint8_t * )dst;
    p[0] = (uint8_t)(w >>  0);
    p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE void store16( void *dst, uint16_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = ( uint8_t * )dst;
    *p++ = ( uint8_t )w; w >>= 8;
    *p++ = ( uint8_t )w;
#endif
}

static BLAKE2_INLINE uint32_t rotr32( const uint32_t w, const unsigned c )
{
    return ( w >> c ) | ( w << ( 32 - c ) );
}

void G(uint8_t r, uint8_t i, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *M);

void ROUND(uint8_t r, uint32_t *V, uint32_t *M);
#endif
