/*
 * SHA1 hash implementation and interface functions
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <string.h>
#include <asm/types.h>

#define os_memcpy	memcpy
#define os_memset	memset
#define os_memcmp	memcmp
#define os_strlen	strlen

#define MAX_SHA1_LEN	32
#define SHA1_MAC_LEN	20

typedef __u8 u8;
typedef __u32 u32;

static inline unsigned int wpa_swap_32(unsigned int v)
{
	return ((v & 0xff) << 24) | ((v & 0xff00) << 8) |
		((v & 0xff0000) >> 8) | (v >> 24);
}
			
#define be_to_host32(n) wpa_swap_32(n)
#define host_to_be32(n) wpa_swap_32(n)

void sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len,
                 u8 *mac);
void hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		      const u8 *addr[], const size_t *len, u8 *mac);
void hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	       u8 *mac);
void sha1_prf(const u8 *key, size_t key_len, const char *label,
	      const u8 *data, size_t data_len, u8 *buf, size_t buf_len);
void sha1_t_prf(const u8 *key, size_t key_len, const char *label,
		const u8 *seed, size_t seed_len, u8 *buf, size_t buf_len);
int tls_prf(const u8 *secret, size_t secret_len,
			 const char *label, const u8 *seed, size_t seed_len,
			 u8 *out, size_t outlen);
#ifdef __cplusplus
extern "C"
#endif
void pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len,
		 int iterations, u8 *buf, size_t buflen);

#ifdef CONFIG_CRYPTO_INTERNAL
struct SHA1Context;

void SHA1Init(struct SHA1Context *context);
void SHA1Update(struct SHA1Context *context, const void *data, u32 len);
void SHA1Final(unsigned char digest[20], struct SHA1Context *context);
#endif /* CONFIG_CRYPTO_INTERNAL */

#endif /* SHA1_H */
