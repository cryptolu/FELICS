; Copyright (C) 2003,2006 B. Poettering
;
; This program is free software; you can redistribute and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version. Whenever you redistribute a copy
; of this document, make sure to include the copyright and license
; agreement without modification.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
; The license text can be found here: http://www.gnu.org/licenses/gpl.txt

;                http://point-at-infinity.org/avraes/
;
; This AES implementation was written in May 2003 by B. Poettering. It is
; published under the terms of the GNU General Public License. If you need
; AES code, but this license is unsuitable for your project, feel free to
; contact me: avraes AT point-at-infinity.org


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;                                 RijndaelFast
;
; This is a microcontroller implementation of the Rijndael block cipher, better
; known as AES. The target device class is Atmel's AVR, a family of very fast
; and very powerful flash MCUs, operating at clock rates up to 16 MHz,
; executing one instruction per clock cycle (16 MIPS). The implementation
; given here is optimized for speed (versus codesize), and achieves an
; encryption rate of more than 100 kByte per second (on a 16MHz MCU).
; The decryption performs about 40% slower than encryption (typical for
; Rijndael).
;
; The implemented algorithm is restricted to block and key sizes of 128 bit.
; Larger key sizes can be obtained by altering the key scheduling code, which
; should be easy. As the cipher's state is completely kept in registers
; (which are limited in number), the block size is not that easy to enlarge.
;
; This implementation makes extensive use of the AVR's "lpm" instruction,
; which loads data bytes from program memory at given addresses (the s-boxes
; are realized that way). Some members of the AVR family don't offer that
; instruction at all (e.g. AT90S1200), others only in a restricted way
; (forcing the target register to be r0). The code below requires the least
; restricted lpm instruction (with free choice of the target register).
; The ATmega161 devices meet the above mentioned requirements.
;
; Statistics:
;
; 16 MHz MCU | clock cycles | blocks per second | bytes per second
; -----------+--------------+-------------------+------------------
; encryption |    2474      |       6467        |      103476
; decryption |    3411      |       4691        |       75051
;
; KEY SETUP TIME
; encryption: 756 clock cycles
; decryption: 756 + 4221 = 4977 clock cycles
;
; CODE SIZE
; instructions: 1306 byte ( 653 words)
; sboxes:       1792 byte ( 896 words) = 7 * 256 byte
; total:        3098 byte (1549 words)
;
; RAM REQUIREMENTS
; 16 * 11 = 176 byte for each expanded key
;
;
; This source code consists of four routines and an example application,
; which encrypts a certain plaintext and decrypts it afterwards with the
; same key. Comments in the code clarify the interaction between the key
; expansion and the encryption/decryption routines.
;
; I encourage to read the following Rijndael-related papers/books/sites:
; [1] "The Design of Rijndael", Daemen & Rijmen, Springer, ISBN 3-540-42580-2
; [2] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/
; [3] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/rijndaeldocV2.zip
; [4] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/atmal.zip
; [5] http://csrc.nist.gov/CryptoToolkit/aes/rijndael/
;
; [1] is *the* book about Rijndael, [2] is the official Rijndael homepage,
; [3] contains the complete Rijndael AES specification, [4] is another
; Rijndael-implementation for AVR MCUs (but much slower than this one,
; taking 3815 clock cycles per encryption), [5] is the official NIST AES
; site with further links.
;
; AVR and ATmega are registered trademarks by the ATMEL corporation.
; See http://www.atmel.com and http://www.atmel.com/products/avr/ for
; further details.



;;; ***************************************************************************
;;; The Rijndael cipher acts on a so-called (128 bit) "state matrix",
;;; represented here by the 4x4 state bytes ST11-ST44. To guarantee maximum
;;; performance on AVR MCUs, these bytes are kept in registers (defaulted to
;;; the 16 low order registers r0-r15, but this may be changed if required).
;;;
;;; The implementation makes use of six auxiliary registers (H1-H5 and I),
;;; some of which must reside in the upper registers (r16-r31). In addition
;;; ramp-registers YH:YL and ZH:ZL are used.
;;;
;;; If the context *really* requires more registers than the remaining ones,
;;; it seems promising to move the I-register to a (fixed) ram location.
;;; In the time crititcal routines the I-value is rarely used, thus the
;;; speed loss obtained by dropping it from the register file is acceptible.

;Alterations done by Luan Cardoso dos Santos @ UniLu:
;Commented out the main funcion, while keeping only the funtions.

.include "m161def.inc"

.def ST11=r0
.def ST21=r1
.def ST31=r2
.def ST41=r3
.def ST12=r4
.def ST22=r5
.def ST32=r6
.def ST42=r7
.def ST13=r8
.def ST23=r9
.def ST33=r10
.def ST43=r11
.def ST14=r12
.def ST24=r13
.def ST34=r14
.def ST44=r15
.def H1=r16
.def H2=r17
.def H3=r18
.def H4=r19
.def H5=r20
.def I=r21
;
;
;main:	cli			; initialize stack
;	ldi r31,HIGH(RAMEND)
;	out SPH,r31
;	ldi r31,LOW(RAMEND)
;	out SPL,r31
;
;	ldi ZH, high(key<<1)	; load key into ST11-ST44
;	ldi ZL, low(key<<1)
;	lpm ST11, Z+
;	lpm ST21, Z+
;	lpm ST31, Z+
;	lpm ST41, Z+
;	lpm ST12, Z+
;	lpm ST22, Z+
;	lpm ST32, Z+
;	lpm ST42, Z+
;	lpm ST13, Z+
;	lpm ST23, Z+
;	lpm ST33, Z+
;	lpm ST43, Z+
;	lpm ST14, Z+
;	lpm ST24, Z+
;	lpm ST34, Z+
;	lpm ST44, Z+
;
;	ldi YH, $00		; expand key to the memory
;	ldi YL, $60		; locations $60..$60+(16*11-1)
;	rcall key_expand
;
;	ldi ZH, high(key<<1)	; load key again
;	ldi ZL, low(key<<1)	; (this time for decryption)
;	lpm ST11, Z+
;	lpm ST21, Z+
;	lpm ST31, Z+
;	lpm ST41, Z+
;	lpm ST12, Z+
;	lpm ST22, Z+
;	lpm ST32, Z+
;	lpm ST42, Z+
;	lpm ST13, Z+
;	lpm ST23, Z+
;	lpm ST33, Z+
;	lpm ST43, Z+
;	lpm ST14, Z+
;	lpm ST24, Z+
;	lpm ST34, Z+
;	lpm ST44, Z+
;
;	ldi YH, $01		; expand it to $120..$120+(16*11-1)
;	ldi YL, $20
;	rcall key_expand
;
;	ldi YH, $01		; make it suitable for decryption
;	ldi YL, $20
;	rcall patch_decryption_key
;
;	ldi ZH, high(text<<1)	; load plaintext into ST11-ST44
;	ldi ZL, low(text<<1)
;	lpm ST11, Z+
;	lpm ST21, Z+
;	lpm ST31, Z+
;	lpm ST41, Z+
;	lpm ST12, Z+
;	lpm ST22, Z+
;	lpm ST32, Z+
;	lpm ST42, Z+
;	lpm ST13, Z+
;	lpm ST23, Z+
;	lpm ST33, Z+
;	lpm ST43, Z+
;	lpm ST14, Z+
;	lpm ST24, Z+
;	lpm ST34, Z+
;	lpm ST44, Z+
;
;	; now the registers ST11-ST44 contain the plaintext given below
;
;	ldi YH, 0		; initialize YH:YL to
;	ldi YL, 0x60		; expanded key and call
;	rcall encrypt		; encryption routine
;
;	; now the registers ST11-ST44 contain the enciphered text
;
;	ldi YH, high($120+16*11); initialize YH:YL to point BEHIND
;	ldi YL, low($120+16*11)	; decryption key material and
;	rcall decrypt		; call decryption routine
;
;	; now the registers ST11-ST44 contain the plaintext again
;
;main0:	rjmp main0		; stop
;
;
;text:
;.db $32,$43,$f6,$a8,$88,$5a,$30,$8d,$31,$31,$98,$a2,$e0,$37,$07,$34
;key:
;.db $2b,$7e,$15,$16,$28,$ae,$d2,$a6,$ab,$f7,$15,$88,$09,$cf,$4f,$3c


;;; ***************************************************************************
;;;
;;; KEY_EXPAND
;;; The following routine implements the Rijndael key expansion algorithm. The
;;; caller supplies the 128 bit key in the registers ST11-ST44 and a pointer
;;; in the YH:YL register pair. The key is expanded to the memory
;;; positions [Y : Y+16*11-1]. Note: the key expansion is necessary for both
;;; encryption and decryption.
;;;
;;; Parameters:
;;;     ST11-ST44:	the 128 bit key
;;;         YH:YL:	pointer to ram location
;;; Touched registers:
;;;     ST11-ST44,H1-H3,ZH,ZL,YH,YL
;;; Clock cycles:	756

key_expand:
	ldi H1, 1
	ldi H2, $1b
	ldi ZH, high(sbox<<1)
	rjmp keyexp1
keyexp0:mov ZL, ST24
	lpm H3, Z
	eor ST11, H3
	eor ST11, H1
	mov ZL, ST34
	lpm H3, Z
	eor ST21, H3
	mov ZL, ST44
	lpm H3, Z
	eor ST31, H3
	mov ZL, ST14
	lpm H3, Z
	eor ST41, H3
	eor ST12, ST11
	eor ST22, ST21
	eor ST32, ST31
	eor ST42, ST41
	eor ST13, ST12
	eor ST23, ST22
	eor ST33, ST32
	eor ST43, ST42
	eor ST14, ST13
	eor ST24, ST23
	eor ST34, ST33
	eor ST44, ST43
	lsl H1
	brcc keyexp1
	eor H1, H2
keyexp1:st Y+, ST11
	st Y+, ST21
	st Y+, ST31
	st Y+, ST41
	st Y+, ST12
	st Y+, ST22
	st Y+, ST32
	st Y+, ST42
	st Y+, ST13
	st Y+, ST23
	st Y+, ST33
	st Y+, ST43
	st Y+, ST14
	st Y+, ST24
	st Y+, ST34
	st Y+, ST44
	cpi H1, $6c
	brne keyexp0
	ret

;;; ***************************************************************************
;;;
;;; PATCH_DECRYPTION_KEY
;;; The following routine applies the MixColumns diffusion operator to the
;;; columns of the expanded key (to be precise:	to all but the first and
;;; last four). This is necessary, as the decryption routine below implements
;;; the so-called "equivalent decryption algorithm" of Rijndael.The original
;;; key material is overwritten by the patched one.
;;; Note: this routine is only needed for decryption purposes!
;;;
;;; Parameters:
;;;         YH:YL:	pointer to expanded key
;;; Touched registers:
;;;     ST11-ST41,H1-H5,I,ZH,ZL,YH,YL
;;; Clock cycles:	4221

patch_decryption_key:
	adiw YH:YL, 16
	ldi I, 35
patchd0:ldd ST11, Y+0
	ldd ST21, Y+1
	ldd ST31, Y+2
	ldd ST41, Y+3
	ldi ZH, high(sbox<<1)
	mov ZL, ST11
	lpm ZL, Z
	ldi ZH, high(isbox0e<<1)
	lpm H1, Z
	ldi ZH, high(isbox09<<1)
	lpm H2, Z
	ldi ZH, high(isbox0d<<1)
	lpm H3, Z
	ldi ZH, high(isbox0b<<1)
	lpm H4, Z
	ldi ZH, high(sbox<<1)
	mov ZL, ST21
	lpm ZL, Z
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(sbox<<1)
	mov ZL, ST31
	lpm ZL, Z
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(sbox<<1)
	mov ZL, ST41
	lpm ZL, Z
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H4, H5
	st Y+, H1
	st Y+, H2
	st Y+, H3
	st Y+, H4
	dec I
	sbrs I, 7
	jmp patchd0
	ret

;;; ***************************************************************************
;;;
;;; ENCRYPT
;;; This routine encrypts a 128 bit plaintext block (supplied in ST11-ST44),
;;; using an expanded key given in YH:YL. The resulting 128 bit ciphertext
;;; block is stored in ST11-ST44.
;;;
;;; Parameters:
;;;         YH:YL:	pointer to expanded key
;;;         ST11-ST44:  128 bit plaintext block
;;; Touched registers:
;;;     ST11-ST41,H1-H5,I,ZH,ZL,YH,YL
;;; Clock cycles:	2474

encrypt:
	rcall encryp1
	ldi ZH, high(sbox<<1)
	ldi I, 8
encryp0:mov ZL, ST11		; 1
	lpm H2, Z
	mov H3, H2
	mov H4, H2
	ldi ZH, high(sbox02<<1)
	lpm H1, Z
	eor H4, H1
	mov ZL, ST22
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor H1, H5
	eor H3, H5
	eor H4, H5
	mov ZL, ST33
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	eor H4, H5
	ldi ZH, high(sbox02<<1)
	lpm H5, Z
	eor H2, H5
	eor H3, H5
	mov ZL, ST44
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	eor H3, H5
	ldd ST11, Y+0
	eor ST11, H1
	mov ZL, ST41		; 2
	ldd ST41, Y+3
	eor ST41, H4
	lpm H1, Z
	mov H4, H1
	mov ST33, H1
	ldi ZH, high(sbox02<<1)
	lpm ST44, Z
	eor ST33, ST44
	mov ZL, ST12
	lpm H5, Z
	eor H1, H5
	eor ST44, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor H4, H5
	eor ST33, H5
	eor ST44, H5
	mov ZL, ST23
	lpm H5, Z
	eor H1, H5
	eor ST33, H5
	eor ST44, H5
	ldi ZH, high(sbox02<<1)
	lpm H5, Z
	eor H1, H5
	eor H4, H5
	mov ZL, ST34
	lpm H5, Z
	eor H4, H5
	eor ST33, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor H1, H5
	eor H4, H5
	eor ST44, H5
	ldd ST12, Y+4
	eor ST12, H1
	ldd ST22, Y+5
	eor ST22, H4
	mov ZL, ST31		; 3
	ldd ST31, Y+2
	eor ST31, H3
	lpm ST34, Z
	mov H3, ST34
	mov H1, ST34
	ldi ZH, high(sbox02<<1)
	lpm H4, Z
	eor H3, H4
	mov ZL, ST42
	ldd ST42, Y+7
	eor ST42, ST44
	lpm H5, Z
	eor H4, H5
	eor H1, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	mov ZL, ST13
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	eor H1, H5
	ldi ZH, high(sbox02<<1)
	lpm H5, Z
	eor ST34, H5
	eor H1, H5
	mov ZL, ST24
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor ST34, H5
	eor H4, H5
	eor H1, H5
	ldd ST13, Y+8
	eor ST13, ST34
	ldd ST23, Y+9
	eor ST23, H3
	mov ZL, ST32		; 4
	ldd ST32, Y+6
	eor ST32, ST33
	ldd ST33, Y+10
	eor ST33, H4
	lpm ST24, Z
	mov ST34, ST24
	mov H4, ST24
	ldi ZH, high(sbox02<<1)
	lpm H3, Z
	eor ST34, H3
	mov ZL, ST43
	ldd ST43, Y+11
	eor ST43, H1
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor ST24, H5
	eor ST34, H5
	eor H3, H5
	mov ZL, ST14
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	ldi ZH, high(sbox02<<1)
	lpm H5, Z
	eor ST24, H5
	eor H4, H5
	mov ZL, ST21
	lpm H5, Z
	eor ST24, H5
	eor ST34, H5
	ldi ZH, high(sbox<<1)
	lpm H5, Z
	eor ST24, H5
	eor H3, H5
	eor H4, H5
	ldd ST21, Y+1
	eor ST21, H2
	ldd ST14, Y+12
	eor ST14, ST24
	ldd ST24, Y+13
	eor ST24, ST34
	ldd ST34, Y+14
	eor ST34, H3
	ldd ST44, Y+15
	eor ST44, H4
	adiw YH:YL, 16
	dec I
	sbrs I,7
	jmp encryp0
	mov ZL, ST11
	lpm ST11, Z
	mov ZL, ST12
	lpm ST12, Z
	mov ZL, ST13
	lpm ST13, Z
	mov ZL, ST14
	lpm ST14, Z
	mov H1, ST21
	mov ZL, ST22
	lpm ST21, Z
	mov ZL, ST23
	lpm ST22, Z
	mov ZL, ST24
	lpm ST23, Z
	mov ZL, H1
	lpm ST24, Z
	mov H1, ST31
	mov ZL, ST33
	lpm ST31, Z
	mov ZL, H1
	lpm ST33, Z
	mov H1, ST32
	mov ZL, ST34
	lpm ST32, Z
	mov ZL, H1
	lpm ST34, Z
	mov H1, ST41
	mov ZL, ST44
	lpm ST41, Z
	mov ZL, ST43
	lpm ST44, Z
	mov ZL, ST42
	lpm ST43, Z
	mov ZL, H1
	lpm ST42, Z
encryp1:ld H1, Y+
	eor ST11, H1
	ld H1, Y+
	eor ST21, H1
	ld H1, Y+
	eor ST31, H1
	ld H1, Y+
	eor ST41, H1
	ld H1, Y+
	eor ST12, H1
	ld H1, Y+
	eor ST22, H1
	ld H1, Y+
	eor ST32, H1
	ld H1, Y+
	eor ST42, H1
	ld H1, Y+
	eor ST13, H1
	ld H1, Y+
	eor ST23, H1
	ld H1, Y+
	eor ST33, H1
	ld H1, Y+
	eor ST43, H1
	ld H1, Y+
	eor ST14, H1
	ld H1, Y+
	eor ST24, H1
	ld H1, Y+
	eor ST34, H1
	ld H1, Y+
	eor ST44, H1
	ret

;;; ***************************************************************************
;;;
;;; DECRYPT
;;; This routine decrypts a 128 bit ciphertext block (given in ST11-ST44),
;;; using an expanded (and patched) key supplied in the 16*11 memory locations
;;; BEFORE YH:YL (YH:YL points behind the last byte of key material!). The
;;; resulting 128 bit plaintext block is stored in ST11-ST44. The "equivalent
;;; decryption algorithm" of Rijndael is implemented, so the MixColumns
;;; diffusion operator has to be applied to the expanded key (done
;;; with the routine patch_decryption_key) before calling the "decrypt"
;;; routine.
;;;
;;; Parameters:
;;;         YH:YL:	pointer behind patched key
;;;         ST11-ST44:  128 bit ciphertext block
;;; Touched registers:
;;;     ST11-ST41,H1-H5,I,ZH,ZL,YH,YL
;;; Clock cycles:	3411

decrypt:rcall decryp1
	ldi I, 8
	ldi ZH, high(isbox0e<<1)
decryp0:sbiw YH:YL, 16
	mov ZL, ST11		; 1
	lpm H1, Z
	ldi ZH, high(isbox09<<1)
	lpm H2, Z
	ldi ZH, high(isbox0d<<1)
	lpm H3, Z
	ldi ZH, high(isbox0b<<1)
	lpm H4, Z
	mov ZL, ST24
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H2, H5
	mov ZL, ST33
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H2, H5
	mov ZL, ST42
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H4, H5
	ldd ST11, Y+0
	eor ST11, H1
	mov ZL, ST21		; 2
	ldd ST21, Y+1
	eor ST21, H2
	lpm H2, Z
	ldi ZH, high(isbox09<<1)
	lpm ST24, Z
	ldi ZH, high(isbox0d<<1)
	lpm ST33, Z
	ldi ZH, high(isbox0b<<1)
	lpm H1, Z
	mov ZL, ST12
	lpm H5, Z
	eor ST33, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor ST24, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H1, H5
	mov ZL, ST34
	lpm H5, Z
	eor ST24, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor ST33, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H2, H5
	mov ZL, ST43
	lpm H5, Z
	eor ST24, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor ST33, H5
	ldd ST12, Y+4
	eor ST12, H1
	ldd ST42, Y+7
	eor ST42, ST33
	mov ZL, ST31		; 3
	ldd ST31, Y+2
	eor ST31, H3
	lpm ST34, Z
	ldi ZH, high(isbox09<<1)
	lpm H3, Z
	ldi ZH, high(isbox0d<<1)
	lpm H1, Z
	ldi ZH, high(isbox0b<<1)
	lpm ST33, Z
	mov ZL, ST13
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor ST34, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor ST33, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H1, H5
	mov ZL, ST22
	lpm H5, Z
	eor ST33, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor ST34, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H1, H5
	mov ZL, ST44
	lpm H5, Z
	eor ST34, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor ST33, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H3, H5
	ldd ST13, Y+8
	eor ST13, H1
	ldd ST43, Y+11
	eor ST43, H3
	ldd ST22, Y+5
	eor ST22, H2
	mov ZL, ST41		; 4
	ldd ST41, Y+3
	eor ST41, H4
	lpm H4, Z
	ldi ZH, high(isbox09<<1)
	lpm H1, Z
	ldi ZH, high(isbox0d<<1)
	lpm H2, Z
	ldi ZH, high(isbox0b<<1)
	lpm H3, Z
	mov ZL, ST14
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H1, H5
	mov ZL, ST23
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H3, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(isbox0b<<1)
	lpm H5, Z
	eor H1, H5
	mov ZL, ST32
	lpm H5, Z
	eor H2, H5
	ldi ZH, high(isbox0d<<1)
	lpm H5, Z
	eor H1, H5
	ldi ZH, high(isbox09<<1)
	lpm H5, Z
	eor H4, H5
	ldi ZH, high(isbox0e<<1)
	lpm H5, Z
	eor H3, H5
	ldd ST14, Y+12
	eor ST14, H1
	ldd ST23, Y+9
	eor ST23, ST33
	ldd ST32, Y+6
	eor ST32, ST24
	ldd ST33, Y+10
	eor ST33, ST34
	ldd ST34, Y+14
	eor ST34, H3
	ldd ST44, Y+15
	eor ST44, H4
	ldd ST24, Y+13
	eor ST24, H2
	dec I
	sbrs I,7
	jmp decryp0
	ldi ZH, high(isbox<<1)
	mov ZL, ST11
	lpm ST11, Z
	mov ZL, ST12
	lpm ST12, Z
	mov ZL, ST13
	lpm ST13, Z
	mov ZL, ST14
	lpm ST14, Z
	mov H1, ST24
	mov ZL, ST23
	lpm ST24, Z
	mov ZL, ST22
	lpm ST23, Z
	mov ZL, ST21
	lpm ST22, Z
	mov ZL, H1
	lpm ST21, Z
	mov H1, ST31
	mov ZL, ST33
	lpm ST31, Z
	mov ZL, H1
	lpm ST33, Z
	mov H1, ST32
	mov ZL, ST34
	lpm ST32, Z
	mov ZL, H1
	lpm ST34, Z
	mov H1, ST41
	mov ZL, ST42
	lpm ST41, Z
	mov ZL, ST43
	lpm ST42, Z
	mov ZL, ST44
	lpm ST43, Z
	mov ZL, H1
	lpm ST44, Z
decryp1:ld H1, -Y
	eor ST44, H1
	ld H1, -Y
	eor ST34, H1
	ld H1, -Y
	eor ST24, H1
	ld H1, -Y
	eor ST14, H1
	ld H1, -Y
	eor ST43, H1
	ld H1, -Y
	eor ST33, H1
	ld H1, -Y
	eor ST23, H1
	ld H1, -Y
	eor ST13, H1
	ld H1, -Y
	eor ST42, H1
	ld H1, -Y
	eor ST32, H1
	ld H1, -Y
	eor ST22, H1
	ld H1, -Y
	eor ST12, H1
	ld H1, -Y
	eor ST41, H1
	ld H1, -Y
	eor ST31, H1
	ld H1, -Y
	eor ST21, H1
	ld H1, -Y
	eor ST11, H1
	ret



;;; ***************************************************************************
;;;
;;; S-BOX
;;; Rijndael consists of a non-linear step in its rounds (called "sbox step"),
;;; generally implemented with hard-coded lookup tables. The implementation
;;; given above makes use of seven lookup tables in total: the sbox itself,
;;; its inverse, and scaled versions of both (e.g. sbox02[] = 2*sbox[]).
;;;
;;; This generous employment of expensive space of flash memory has two
;;; important advantages: excellent performance and protection against
;;; timing and power measurement attacks.
;;;
;;; The seven tables have to be aligned to a flash position with its lower
;;; address byte equal to $00. In assembler syntax: low(sbox<<1) == 0.
;;; To ensure the proper alignment of the sboxes, the assembler directive
;;; .ORG is used (below the sboxes are defined to begin at $800). Note, that
;;; any other address can be used as well, as long as the lower byte is equal
;;; to $00.
;;;
;;; The order of the sboxes is totally arbitrary. They even do not have to be
;;; allocated in adjacent memory areas.

.CSEG
.ORG $800

sbox:
.db $63,$7c,$77,$7b,$f2,$6b,$6f,$c5,$30,$01,$67,$2b,$fe,$d7,$ab,$76
.db $ca,$82,$c9,$7d,$fa,$59,$47,$f0,$ad,$d4,$a2,$af,$9c,$a4,$72,$c0
.db $b7,$fd,$93,$26,$36,$3f,$f7,$cc,$34,$a5,$e5,$f1,$71,$d8,$31,$15
.db $04,$c7,$23,$c3,$18,$96,$05,$9a,$07,$12,$80,$e2,$eb,$27,$b2,$75
.db $09,$83,$2c,$1a,$1b,$6e,$5a,$a0,$52,$3b,$d6,$b3,$29,$e3,$2f,$84
.db $53,$d1,$00,$ed,$20,$fc,$b1,$5b,$6a,$cb,$be,$39,$4a,$4c,$58,$cf
.db $d0,$ef,$aa,$fb,$43,$4d,$33,$85,$45,$f9,$02,$7f,$50,$3c,$9f,$a8
.db $51,$a3,$40,$8f,$92,$9d,$38,$f5,$bc,$b6,$da,$21,$10,$ff,$f3,$d2
.db $cd,$0c,$13,$ec,$5f,$97,$44,$17,$c4,$a7,$7e,$3d,$64,$5d,$19,$73
.db $60,$81,$4f,$dc,$22,$2a,$90,$88,$46,$ee,$b8,$14,$de,$5e,$0b,$db
.db $e0,$32,$3a,$0a,$49,$06,$24,$5c,$c2,$d3,$ac,$62,$91,$95,$e4,$79
.db $e7,$c8,$37,$6d,$8d,$d5,$4e,$a9,$6c,$56,$f4,$ea,$65,$7a,$ae,$08
.db $ba,$78,$25,$2e,$1c,$a6,$b4,$c6,$e8,$dd,$74,$1f,$4b,$bd,$8b,$8a
.db $70,$3e,$b5,$66,$48,$03,$f6,$0e,$61,$35,$57,$b9,$86,$c1,$1d,$9e
.db $e1,$f8,$98,$11,$69,$d9,$8e,$94,$9b,$1e,$87,$e9,$ce,$55,$28,$df
.db $8c,$a1,$89,$0d,$bf,$e6,$42,$68,$41,$99,$2d,$0f,$b0,$54,$bb,$16

sbox02:
.db $c6,$f8,$ee,$f6,$ff,$d6,$de,$91,$60,$02,$ce,$56,$e7,$b5,$4d,$ec
.db $8f,$1f,$89,$fa,$ef,$b2,$8e,$fb,$41,$b3,$5f,$45,$23,$53,$e4,$9b
.db $75,$e1,$3d,$4c,$6c,$7e,$f5,$83,$68,$51,$d1,$f9,$e2,$ab,$62,$2a
.db $08,$95,$46,$9d,$30,$37,$0a,$2f,$0e,$24,$1b,$df,$cd,$4e,$7f,$ea
.db $12,$1d,$58,$34,$36,$dc,$b4,$5b,$a4,$76,$b7,$7d,$52,$dd,$5e,$13
.db $a6,$b9,$00,$c1,$40,$e3,$79,$b6,$d4,$8d,$67,$72,$94,$98,$b0,$85
.db $bb,$c5,$4f,$ed,$86,$9a,$66,$11,$8a,$e9,$04,$fe,$a0,$78,$25,$4b
.db $a2,$5d,$80,$05,$3f,$21,$70,$f1,$63,$77,$af,$42,$20,$e5,$fd,$bf
.db $81,$18,$26,$c3,$be,$35,$88,$2e,$93,$55,$fc,$7a,$c8,$ba,$32,$e6
.db $c0,$19,$9e,$a3,$44,$54,$3b,$0b,$8c,$c7,$6b,$28,$a7,$bc,$16,$ad
.db $db,$64,$74,$14,$92,$0c,$48,$b8,$9f,$bd,$43,$c4,$39,$31,$d3,$f2
.db $d5,$8b,$6e,$da,$01,$b1,$9c,$49,$d8,$ac,$f3,$cf,$ca,$f4,$47,$10
.db $6f,$f0,$4a,$5c,$38,$57,$73,$97,$cb,$a1,$e8,$3e,$96,$61,$0d,$0f
.db $e0,$7c,$71,$cc,$90,$06,$f7,$1c,$c2,$6a,$ae,$69,$17,$99,$3a,$27
.db $d9,$eb,$2b,$22,$d2,$a9,$07,$33,$2d,$3c,$15,$c9,$87,$aa,$50,$a5
.db $03,$59,$09,$1a,$65,$d7,$84,$d0,$82,$29,$5a,$1e,$7b,$a8,$6d,$2c

isbox:
.db $52,$09,$6a,$d5,$30,$36,$a5,$38,$bf,$40,$a3,$9e,$81,$f3,$d7,$fb
.db $7c,$e3,$39,$82,$9b,$2f,$ff,$87,$34,$8e,$43,$44,$c4,$de,$e9,$cb
.db $54,$7b,$94,$32,$a6,$c2,$23,$3d,$ee,$4c,$95,$0b,$42,$fa,$c3,$4e
.db $08,$2e,$a1,$66,$28,$d9,$24,$b2,$76,$5b,$a2,$49,$6d,$8b,$d1,$25
.db $72,$f8,$f6,$64,$86,$68,$98,$16,$d4,$a4,$5c,$cc,$5d,$65,$b6,$92
.db $6c,$70,$48,$50,$fd,$ed,$b9,$da,$5e,$15,$46,$57,$a7,$8d,$9d,$84
.db $90,$d8,$ab,$00,$8c,$bc,$d3,$0a,$f7,$e4,$58,$05,$b8,$b3,$45,$06
.db $d0,$2c,$1e,$8f,$ca,$3f,$0f,$02,$c1,$af,$bd,$03,$01,$13,$8a,$6b
.db $3a,$91,$11,$41,$4f,$67,$dc,$ea,$97,$f2,$cf,$ce,$f0,$b4,$e6,$73
.db $96,$ac,$74,$22,$e7,$ad,$35,$85,$e2,$f9,$37,$e8,$1c,$75,$df,$6e
.db $47,$f1,$1a,$71,$1d,$29,$c5,$89,$6f,$b7,$62,$0e,$aa,$18,$be,$1b
.db $fc,$56,$3e,$4b,$c6,$d2,$79,$20,$9a,$db,$c0,$fe,$78,$cd,$5a,$f4
.db $1f,$dd,$a8,$33,$88,$07,$c7,$31,$b1,$12,$10,$59,$27,$80,$ec,$5f
.db $60,$51,$7f,$a9,$19,$b5,$4a,$0d,$2d,$e5,$7a,$9f,$93,$c9,$9c,$ef
.db $a0,$e0,$3b,$4d,$ae,$2a,$f5,$b0,$c8,$eb,$bb,$3c,$83,$53,$99,$61
.db $17,$2b,$04,$7e,$ba,$77,$d6,$26,$e1,$69,$14,$63,$55,$21,$0c,$7d

isbox0e:
.db $51,$7e,$1a,$3a,$3b,$1f,$ac,$4b,$20,$ad,$88,$f5,$4f,$c5,$26,$b5
.db $de,$25,$45,$5d,$c3,$81,$8d,$6b,$03,$15,$bf,$95,$d4,$58,$49,$8e
.db $75,$f4,$99,$27,$be,$f0,$c9,$7d,$63,$e5,$97,$62,$b1,$bb,$fe,$f9
.db $70,$8f,$94,$52,$ab,$72,$e3,$66,$b2,$2f,$86,$d3,$30,$23,$02,$ed
.db $8a,$a7,$f3,$4e,$65,$06,$d1,$c4,$34,$a2,$05,$a4,$0b,$40,$5e,$bd
.db $3e,$96,$dd,$4d,$91,$71,$04,$60,$19,$d6,$89,$67,$b0,$07,$e7,$79
.db $a1,$7c,$f8,$00,$09,$32,$1e,$6c,$fd,$0f,$3d,$36,$0a,$68,$9b,$24
.db $0c,$93,$b4,$1b,$80,$61,$5a,$1c,$e2,$c0,$3c,$12,$0e,$f2,$2d,$14
.db $57,$af,$ee,$a3,$f7,$5c,$44,$5b,$8b,$cb,$b6,$b8,$d7,$42,$13,$84
.db $85,$d2,$ae,$c7,$1d,$dc,$0d,$77,$2b,$a9,$11,$47,$a8,$a0,$56,$22
.db $87,$d9,$8c,$98,$a6,$a5,$da,$3f,$2c,$50,$6a,$54,$f6,$90,$2e,$82
.db $9f,$69,$6f,$cf,$c8,$10,$e8,$db,$cd,$6e,$ec,$83,$e6,$aa,$21,$ef
.db $ba,$4a,$ea,$29,$31,$2a,$c6,$35,$74,$fc,$e0,$33,$f1,$41,$7f,$17
.db $76,$43,$cc,$e4,$9e,$4c,$c1,$46,$9d,$01,$fa,$fb,$b3,$92,$e9,$6d
.db $9a,$37,$59,$eb,$ce,$b7,$e1,$7a,$9c,$55,$18,$73,$53,$5f,$df,$78
.db $ca,$b9,$38,$c2,$16,$bc,$28,$ff,$39,$08,$d8,$64,$7b,$d5,$48,$d0

isbox09:
.db $f4,$41,$17,$27,$ab,$9d,$fa,$e3,$30,$76,$cc,$02,$e5,$2a,$35,$62
.db $b1,$ba,$ea,$fe,$2f,$4c,$46,$d3,$8f,$92,$6d,$52,$be,$74,$e0,$c9
.db $c2,$8e,$58,$b9,$e1,$88,$20,$ce,$df,$1a,$51,$53,$64,$6b,$81,$08
.db $48,$45,$de,$7b,$73,$4b,$1f,$55,$eb,$b5,$c5,$37,$28,$bf,$03,$16
.db $cf,$79,$07,$69,$da,$05,$34,$a6,$2e,$f3,$8a,$f6,$83,$60,$71,$6e
.db $21,$dd,$3e,$e6,$54,$c4,$06,$50,$98,$bd,$40,$d9,$e8,$89,$19,$c8
.db $7c,$42,$84,$00,$80,$2b,$11,$5a,$0e,$85,$ae,$2d,$0f,$5c,$5b,$36
.db $0a,$57,$ee,$9b,$c0,$dc,$77,$12,$93,$a0,$22,$1b,$09,$8b,$b6,$1e
.db $f1,$75,$99,$7f,$01,$72,$66,$fb,$43,$23,$ed,$e4,$31,$63,$97,$c6
.db $4a,$bb,$f9,$29,$9e,$b2,$86,$c1,$b3,$70,$94,$e9,$fc,$f0,$7d,$33
.db $49,$38,$ca,$d4,$f5,$7a,$b7,$ad,$3a,$78,$5f,$7e,$8d,$d8,$39,$c3
.db $5d,$d0,$d5,$25,$ac,$18,$9c,$3b,$26,$59,$9a,$4f,$95,$ff,$bc,$15
.db $e7,$6f,$9f,$b0,$a4,$3f,$a5,$a2,$4e,$82,$90,$a7,$04,$ec,$cd,$91
.db $4d,$ef,$aa,$96,$d1,$6a,$2c,$65,$5e,$8c,$87,$0b,$67,$db,$10,$d6
.db $d7,$a1,$f8,$13,$a9,$61,$1c,$47,$d2,$f2,$14,$c7,$f7,$fd,$3d,$44
.db $af,$68,$24,$a3,$1d,$e2,$3c,$0d,$a8,$0c,$b4,$56,$cb,$32,$6c,$b8

isbox0d:
.db $a7,$65,$a4,$5e,$6b,$45,$58,$03,$fa,$6d,$76,$4c,$d7,$cb,$44,$a3
.db $5a,$1b,$0e,$c0,$75,$f0,$97,$f9,$5f,$9c,$7a,$59,$83,$21,$69,$c8
.db $89,$79,$3e,$71,$4f,$ad,$ac,$3a,$4a,$31,$33,$7f,$77,$ae,$a0,$2b
.db $68,$fd,$6c,$f8,$d3,$02,$8f,$ab,$28,$c2,$7b,$08,$87,$a5,$6a,$82
.db $1c,$b4,$f2,$e2,$f4,$be,$62,$fe,$53,$55,$e1,$eb,$ec,$ef,$9f,$10
.db $8a,$06,$05,$bd,$8d,$5d,$d4,$15,$fb,$e9,$43,$9e,$42,$8b,$5b,$ee
.db $0a,$0f,$1e,$00,$86,$ed,$70,$72,$ff,$38,$d5,$39,$d9,$a6,$54,$2e
.db $67,$e7,$96,$91,$c5,$20,$4b,$1a,$ba,$2a,$e0,$17,$0d,$c7,$a8,$a9
.db $19,$07,$dd,$60,$26,$f5,$3b,$7e,$29,$c6,$fc,$f1,$dc,$85,$22,$11
.db $24,$3d,$32,$a1,$2f,$30,$52,$e3,$16,$b9,$48,$64,$8c,$3f,$2c,$90
.db $4e,$d1,$a2,$0b,$81,$de,$8e,$bf,$9d,$92,$cc,$46,$13,$b8,$f7,$af
.db $80,$93,$2d,$12,$99,$7d,$63,$bb,$78,$18,$b7,$9a,$6e,$e6,$cf,$e8
.db $9b,$36,$09,$7c,$b2,$23,$94,$66,$bc,$ca,$d0,$d8,$98,$da,$50,$f6
.db $d6,$b0,$4d,$04,$b5,$88,$1f,$51,$ea,$35,$74,$41,$1d,$d2,$56,$47
.db $61,$0c,$14,$3c,$27,$c9,$e5,$b1,$df,$73,$ce,$37,$cd,$aa,$6f,$db
.db $f3,$c4,$34,$40,$c3,$25,$49,$95,$01,$b3,$e4,$c1,$84,$b6,$5c,$57

isbox0b:
.db $50,$53,$c3,$96,$cb,$f1,$ab,$93,$55,$f6,$91,$25,$fc,$d7,$80,$8f
.db $49,$67,$98,$e1,$02,$12,$a3,$c6,$e7,$95,$eb,$da,$2d,$d3,$29,$44
.db $6a,$78,$6b,$dd,$b6,$17,$66,$b4,$18,$82,$60,$45,$e0,$84,$1c,$94
.db $58,$19,$87,$b7,$23,$e2,$57,$2a,$07,$03,$9a,$a5,$f2,$b2,$ba,$5c
.db $2b,$92,$f0,$a1,$cd,$d5,$1f,$8a,$9d,$a0,$32,$75,$39,$aa,$06,$51
.db $f9,$3d,$ae,$46,$b5,$05,$6f,$ff,$24,$97,$cc,$77,$bd,$88,$38,$db
.db $47,$e9,$c9,$00,$83,$48,$ac,$4e,$fb,$56,$1e,$27,$64,$21,$d1,$3a
.db $b1,$0f,$d2,$9e,$4f,$a2,$69,$16,$0a,$e5,$43,$1d,$0b,$ad,$b9,$c8
.db $85,$4c,$bb,$fd,$9f,$bc,$c5,$34,$76,$dc,$68,$63,$ca,$10,$40,$20
.db $7d,$f8,$11,$6d,$4b,$f3,$ec,$d0,$6c,$99,$fa,$22,$c4,$1a,$d8,$ef
.db $c7,$c1,$fe,$36,$cf,$28,$26,$a4,$e4,$0d,$9b,$62,$c2,$e8,$5e,$f5
.db $be,$7c,$a9,$b3,$3b,$a7,$6e,$7b,$09,$f4,$01,$a8,$65,$7e,$08,$e6
.db $d9,$ce,$d4,$d6,$af,$31,$30,$c0,$37,$a6,$b0,$15,$4a,$f7,$0e,$2f
.db $8d,$4d,$54,$df,$e3,$1b,$b8,$7f,$04,$5d,$73,$2e,$5a,$52,$33,$13
.db $8c,$7a,$8e,$89,$ee,$35,$ed,$3c,$59,$3f,$79,$bf,$ea,$5b,$14,$86
.db $81,$3e,$2c,$5f,$72,$0c,$8b,$41,$71,$de,$9c,$90,$61,$70,$74,$42
