/* JavaScript password hash generator.
 * $Id: pwd.js,v 1.5 2004/10/09 09:41:38 emikulic Exp $
 *
 * Copyright (c) 2004, Emil Mikulic.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



/* Emil's adaptation of crypt() from FreeSec: libcrypt
 * Taken from $OpenBSD: crypt.c,v 1.18 2003/08/12 01:22:17 deraadt Exp $
 * Original license:
 * Copyright (c) 1994 David Burren
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The JavaScript adaptation is copyright (c) 2004 Emil Mikulic.
 */


jsdes = function() {
	this.ascii64 =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	this.des_IP = [
		58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
	];

	this.des_key_perm = [
		57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
	];

	this.des_key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

	this.des_comp_perm = [
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
	];

	this.des_sbox = [
		[
			14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
		],
		[
			15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
		],
		[
			10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
		],
		[
			7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
		],
		[
			2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
		],
		[
			12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
		],
		[
			4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
		],
		[
			13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
		]
	];

	this.des_pbox = [
		16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
	];

	this.des_bits32 = [
		0x80000000, 0x40000000, 0x20000000, 0x10000000,
		0x08000000, 0x04000000, 0x02000000, 0x01000000,
		0x00800000, 0x00400000, 0x00200000, 0x00100000,
		0x00080000, 0x00040000, 0x00020000, 0x00010000,
		0x00008000, 0x00004000, 0x00002000, 0x00001000,
		0x00000800, 0x00000400, 0x00000200, 0x00000100,
		0x00000080, 0x00000040, 0x00000020, 0x00000010,
		0x00000008, 0x00000004, 0x00000002, 0x00000001
	];

	this.bits28 = [
		0x08000000, 0x04000000, 0x02000000, 0x01000000,
		0x00800000, 0x00400000, 0x00200000, 0x00100000,
		0x00080000, 0x00040000, 0x00020000, 0x00010000,
		0x00008000, 0x00004000, 0x00002000, 0x00001000,
		0x00000800, 0x00000400, 0x00000200, 0x00000100,
		0x00000080, 0x00000040, 0x00000020, 0x00000010,
		0x00000008, 0x00000004, 0x00000002, 0x00000001
	];

	this.bits24 = [
		0x00800000, 0x00400000, 0x00200000, 0x00100000,
		0x00080000, 0x00040000, 0x00020000, 0x00010000,
		0x00008000, 0x00004000, 0x00002000, 0x00001000,
		0x00000800, 0x00000400, 0x00000200, 0x00000100,
		0x00000080, 0x00000040, 0x00000020, 0x00000010,
		0x00000008, 0x00000004, 0x00000002, 0x00000001
	];

	this.des_bits8 = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

    this.u_sbox = new Array(8);
		this.m_sbox = new Array(4);
		this.init_perm = new Array(64);
		this.final_perm = new Array(64);
		this.inv_key_perm = new Array(64);
		this.u_key_perm = new Array(56);
		this.inv_comp_perm = new Array(56);
		this.ip_maskl = new Array(8);
		this.ip_maskr = new Array(8);
		this.fp_maskl = new Array(8);
		this.fp_maskr = new Array(8);
		this.un_pbox = new Array(32);
		this.psbox = new Array(4);
		this.key_perm_maskl = new Array(8);
		this.key_perm_maskr = new Array(8);
		this.comp_maskl = new Array(8);
		this.comp_maskr = new Array(8);
		this.en_keysl = new Array(16);
		this.en_keysr = new Array(16);
		this.saltbits = null;
		this.des_r0 = null;
		this.des_r1 = null;
	/*
	 * Invert the S-boxes, reordering the input bits.
	 */
	for (i = 0; i < 8; i++) {
		this.u_sbox[i] = new Array(64);
		for (j = 0; j < 64; j++) {
			b = (j & 0x20) | ((j & 1) << 4) | ((j >> 1) & 0xf);
			this.u_sbox[i][j] = this.des_sbox[i][b];
		}
	}

	/*
	 * Convert the inverted S-boxes into 4 arrays of 8 bits.
	 * Each will handle 12 bits of the S-box input.
	 */
	for (b = 0; b < 4; b++) {
		this.m_sbox[b] = new Array(4096);
		for (i = 0; i < 64; i++)
			for (j = 0; j < 64; j++)
				this.m_sbox[b][(i << 6) | j] =
					(this.u_sbox[(b << 1)][i] << 4) |
					this.u_sbox[(b << 1) + 1][j];
	}

	/*
	 * Set up the initial & final permutations into a useful form, and
	 * initialise the inverted key permutation.
	 */
	for (i = 0; i < 64; i++) {
		this.init_perm[this.final_perm[i] = this.des_IP[i] - 1] = i;
		this.inv_key_perm[i] = 255;
	}

	/*
	 * Invert the key permutation and initialise the inverted key
	 * compression permutation.
	 */
	for (i = 0; i < 56; i++) {
		this.u_key_perm[i] = this.des_key_perm[i] - 1;
		this.inv_key_perm[this.des_key_perm[i] - 1] = i;
		this.inv_comp_perm[i] = 255;
	}

	/*
	 * Invert the key compression permutation.
	 */
	for (i = 0; i < 48; i++) {
		this.inv_comp_perm[this.des_comp_perm[i] - 1] = i;
	}

	/*
	 * Set up the OR-mask arrays for the initial and final permutations,
	 * and for the key initial and compression permutations.
	 */
	for (k = 0; k < 8; k++) {
		this.ip_maskl[k] = new Array(256);
		this.ip_maskr[k] = new Array(256);
		this.fp_maskl[k] = new Array(256);
		this.fp_maskr[k] = new Array(256);
		this.key_perm_maskl[k] = new Array(128);
		this.key_perm_maskr[k] = new Array(128);
		this.comp_maskl[k] = new Array(128);
		this.comp_maskr[k] = new Array(128);

		for (i = 0; i < 256; i++) {
			this.ip_maskl[k][i] = 0;
			this.ip_maskr[k][i] = 0;
			this.fp_maskl[k][i] = 0;
			this.fp_maskr[k][i] = 0;
			for (j = 0; j < 8; j++) {
				inbit = 8 * k + j;
				if (i & this.des_bits8[j]) {
					if ((obit = this.init_perm[inbit]) < 32)
						this.ip_maskl[k][i] |=
							this.des_bits32[obit];
					else
						this.ip_maskr[k][i] |=
							this.des_bits32[obit - 32];

					if ((obit = this.final_perm[inbit]) < 32)
						this.fp_maskl[k][i] |=
							this.des_bits32[obit];
					else
						this.fp_maskr[k][i] |=
							this.des_bits32[obit - 32];
				}
			}
		}
		for (i = 0; i < 128; i++) {
			this.key_perm_maskl[k][i] = 0;
			this.key_perm_maskr[k][i] = 0;
			for (j = 0; j < 7; j++) {
				inbit = 8 * k + j;
				if (i & this.des_bits8[j + 1]) {
					if ((obit = this.inv_key_perm[inbit]) == 255)
						continue;
					if (obit < 28)
						this.key_perm_maskl[k][i] |=
							this.bits28[obit];
					else
						this.key_perm_maskr[k][i] |=
							this.bits28[obit - 28];
				}
			}
			this.comp_maskl[k][i] = 0;
			this.comp_maskr[k][i] = 0;
			for (j = 0; j < 7; j++) {
				inbit = 7 * k + j;
				if (i & this.des_bits8[j + 1]) {
					if ((obit = this.inv_comp_perm[inbit]) == 255)
						continue;
					if (obit < 24)
						this.comp_maskl[k][i] |=
							this.bits24[obit];
					else
						this.comp_maskr[k][i] |=
							this.bits24[obit - 24];
				}
			}
		}
	}

	/*
	 * Invert the P-box permutation, and convert into OR-masks for
	 * handling the output of the S-box arrays setup above.
	 */
	for (i = 0; i < 32; i++)
		this.un_pbox[this.des_pbox[i] - 1] = i;

	for (b = 0; b < 4; b++) {
		this.psbox[b] = new Array(256);
		for (i = 0; i < 256; i++) {
			this.psbox[b][i] = 0;
			for (j = 0; j < 8; j++) {
				if (i & this.des_bits8[j])
					this.psbox[b][i] |=
						this.des_bits32[this.un_pbox[8 * b + j]];
			}
		}
	}
};
jsdes.ascii_to_bin = function(ch) {
	var lz = "z".charCodeAt(0),
		la = "a".charCodeAt(0),
		uz = "Z".charCodeAt(0),
		ua = "A".charCodeAt(0),
		ni = "9".charCodeAt(0),
		dt = ".".charCodeAt(0);

	if (ch > lz) return 0;
	if (ch >= la) return (ch - la + 38);
	if (ch > uz) return 0;
	if (ch >= ua) return (ch - ua + 12);
	if (ch > ni) return 0;
	if (ch >= dt) return (ch - dt);
	return 0;
};



jsdes.des_setkey = function(key) {
	var rawkey0, rawkey1, k0, k1;

	rawkey0 = (key[0] << 24) |
		(key[1] << 16) |
		(key[2] << 8) |
		(key[3] << 0);

	rawkey1 = (key[4] << 24) |
		(key[5] << 16) |
		(key[6] << 8) |
		(key[7] << 0);

	/* Do key permutation and split into two 28-bit subkeys. */
	k0 = this.key_perm_maskl[0][rawkey0 >>> 25] | this.key_perm_maskl[1][(rawkey0 >>> 17) & 0x7f] | this.key_perm_maskl[2][(rawkey0 >>> 9) & 0x7f] | this.key_perm_maskl[3][(rawkey0 >>> 1) & 0x7f] | this.key_perm_maskl[4][rawkey1 >>> 25] | this.key_perm_maskl[5][(rawkey1 >>> 17) & 0x7f] | this.key_perm_maskl[6][(rawkey1 >>> 9) & 0x7f] | this.key_perm_maskl[7][(rawkey1 >>> 1) & 0x7f];
	k1 = this.key_perm_maskr[0][rawkey0 >>> 25] | this.key_perm_maskr[1][(rawkey0 >>> 17) & 0x7f] | this.key_perm_maskr[2][(rawkey0 >>> 9) & 0x7f] | this.key_perm_maskr[3][(rawkey0 >>> 1) & 0x7f] | this.key_perm_maskr[4][rawkey1 >>> 25] | this.key_perm_maskr[5][(rawkey1 >>> 17) & 0x7f] | this.key_perm_maskr[6][(rawkey1 >>> 9) & 0x7f] | this.key_perm_maskr[7][(rawkey1 >>> 1) & 0x7f];

	/* Rotate subkeys and do compression permutation. */
	var shifts = 0,
		round;
	for (round = 0; round < 16; round++) {
		var t0, t1;

		shifts += this.des_key_shifts[round];

		t0 = (k0 << shifts) | (k0 >>> (28 - shifts));
		t1 = (k1 << shifts) | (k1 >>> (28 - shifts));

		this.en_keysl[round] = this.comp_maskl[0][(t0 >>> 21) & 0x7f] | this.comp_maskl[1][(t0 >>> 14) & 0x7f] | this.comp_maskl[2][(t0 >>> 7) & 0x7f] | this.comp_maskl[3][t0 & 0x7f] | this.comp_maskl[4][(t1 >>> 21) & 0x7f] | this.comp_maskl[5][(t1 >>> 14) & 0x7f] | this.comp_maskl[6][(t1 >>> 7) & 0x7f] | this.comp_maskl[7][t1 & 0x7f];

		this.en_keysr[round] = this.comp_maskr[0][(t0 >>> 21) & 0x7f] | this.comp_maskr[1][(t0 >>> 14) & 0x7f] | this.comp_maskr[2][(t0 >>> 7) & 0x7f] | this.comp_maskr[3][t0 & 0x7f] | this.comp_maskr[4][(t1 >>> 21) & 0x7f] | this.comp_maskr[5][(t1 >>> 14) & 0x7f] | this.comp_maskr[6][(t1 >>> 7) & 0x7f] | this.comp_maskr[7][t1 & 0x7f];
	}
};


jsdes.des_setup_salt = function(salt) {
	this.saltbits = 0;
	saltbit = 1;
	obit = 0x800000;
	for (i = 0; i < 24; i++) {
		if (salt & saltbit)
			this.saltbits |= obit;
		saltbit <<= 1;
		obit >>= 1;
	}
};



jsdes.des_do_des = function() {
	var l, r, f, r48l, r48r;
	var count = 25;

	/* Don't bother with initial permutation. */
	l = r = 0;

	while (count--) {
		/* Do each round. */
		kl = 0;
		kr = 0;
		var round = 16;
		while (round--) {
			/* Expand R to 48 bits (simulate the E-box). */
			r48l = ((r & 0x00000001) << 23) | ((r & 0xf8000000) >>> 9) | ((r & 0x1f800000) >>> 11) | ((r & 0x01f80000) >>> 13) | ((r & 0x001f8000) >>> 15);

			r48r = ((r & 0x0001f800) << 7) | ((r & 0x00001f80) << 5) | ((r & 0x000001f8) << 3) | ((r & 0x0000001f) << 1) | ((r & 0x80000000) >>> 31);
			/*
			 * Do salting for crypt() and friends, and
			 * XOR with the permuted key.
			 */
			f = (r48l ^ r48r) & this.saltbits;
			r48l ^= f ^ this.en_keysl[kl++];
			r48r ^= f ^ this.en_keysr[kr++];
			/*
			 * Do sbox lookups (which shrink it back to 32 bits)
			 * and do the pbox permutation at the same time.
			 */
			f = this.psbox[0][this.m_sbox[0][r48l >> 12]] | this.psbox[1][this.m_sbox[1][r48l & 0xfff]] | this.psbox[2][this.m_sbox[2][r48r >> 12]] | this.psbox[3][this.m_sbox[3][r48r & 0xfff]];
			/*
			 * Now that we've permuted things, complete f().
			 */
			f ^= l;
			l = r;
			r = f;
		}
		r = l;
		l = f;
	}

	/* Final permutation (inverse of IP). */
	this.des_r0 = this.fp_maskl[0][l >>> 24] | this.fp_maskl[1][(l >>> 16) & 0xff] | this.fp_maskl[2][(l >>> 8) & 0xff] | this.fp_maskl[3][l & 0xff] | this.fp_maskl[4][r >>> 24] | this.fp_maskl[5][(r >>> 16) & 0xff] | this.fp_maskl[6][(r >>> 8) & 0xff] | this.fp_maskl[7][r & 0xff];
	this.des_r1 = this.fp_maskr[0][l >>> 24] | this.fp_maskr[1][(l >>> 16) & 0xff] | this.fp_maskr[2][(l >>> 8) & 0xff] | this.fp_maskr[3][l & 0xff] | this.fp_maskr[4][r >>> 24] | this.fp_maskr[5][(r >>> 16) & 0xff] | this.fp_maskr[6][(r >>> 8) & 0xff] | this.fp_maskr[7][r & 0xff];
};

jsdes.descrypt = function(key, salt_str) {
	var keybuf = new Array(8);
	var output = salt_str.slice(0, 2);

	q = 0;
	keypos = 0;
	while (q < 8) {
		keybuf[q] = key.charCodeAt(keypos) << 1;
		q++;
		if (keypos < key.length) keypos++;
	}

	this.des_setkey(keybuf);

	/* This is the "old style" DES crypt. */
	var salt = (this.ascii_to_bin(salt_str.charCodeAt(1)) << 6) |
		this.ascii_to_bin(salt_str.charCodeAt(0));
	this.des_setup_salt(salt);
	this.des_do_des();

	l = (this.des_r0 >>> 8);
	output += this.ascii64.charAt((l >>> 18) & 0x3f);
	output += this.ascii64.charAt((l >>> 12) & 0x3f);
	output += this.ascii64.charAt((l >>> 6) & 0x3f);
	output += this.ascii64.charAt((l >>> 0) & 0x3f);

	l = (this.des_r0 << 16) | ((this.des_r1 >>> 16) & 0xffff);
	output += this.ascii64.charAt((l >>> 18) & 0x3f);
	output += this.ascii64.charAt((l >>> 12) & 0x3f);
	output += this.ascii64.charAt((l >>> 6) & 0x3f);
	output += this.ascii64.charAt((l >>> 0) & 0x3f);

	l = (this.des_r1 << 2);
	output += this.ascii64.charAt((l >>> 12) & 0x3f);
	output += this.ascii64.charAt((l >>> 6) & 0x3f);
	output += this.ascii64.charAt((l >>> 0) & 0x3f);

	return output;
};

module.exports.jsdes = jsdes;
