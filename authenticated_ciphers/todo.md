Authenticated Encryption module of FELICS
===============================================================================

This file is a centralized TODO and notes for the authenticated encryption module of FELICS. Old information from the previous owner is kept in ./notes

Created in 2018-09-20 by Luan CARDOSO DOS SANTOS
luan.cardoso@uni.lu

--------------------------------------------------------------------------------

Tasks
================================================================================

## Open tasks
<!--
- Task Description (isodate, owner)
-->
- [ ] Implement Xoodyak
- [ ] Other NIST implementations on.
    - [x] Define which ones should be added to FELICS. > Leo's list.

## Closed Tasks
<!--
- Task Description (isodate, owner)(isodate finished)
-->
- [x] Implement ASCON128-a (Luan, 2019-06-11)
- Implement Schwaemm (Luan, 2019-05-31)
    - SCHWAEMM_192_192_192_384_192_v01 -> Schwaemm 192 192
        - Base version, modified for in-place encryption, with a temporary variable `uint8_t tmp[BYTE(rate)]`.
    - SCHWAEMM_256_192_256_384_128_v01 -> Schwaemm 256 128
    - SCHWAEMM_128_128_128_256_128_v01 -> Schwaemm 128 128
    - SCHWAEMM_256_256_256_512_256_v01 -> Schwaemm 256 256


Notes
================================================================================


## SCHWAEMM

- There are optmized asm implementations for SCHWAEMM, but they were not added to FELICS at first, since it would not be correct to have a C reference implementation for all the other ciphers while we use a super fast ASM implementation.
- ASM sources are applied to SPARKLE permutation, and were written for Cortex-M3 and for the 8bit AVR.

## ASCON
- We wont implement ASCON-80pq. There is no interest in this framework for Quantum key-search.
## MISC:

Algorithms to implement, acording to Leo:
- Sparkle (obviously)
- Xoodyak
- Gimli
- Ascon
- Photon-Beetle
- ACE/SpoC/SPIX
- SNEIK1.1
- WAGE
- Shamash
- KNOT


List of ciphers without comments (updated 2019-06-05, 34 total items):
```
['ACE', 'ASCON', 'COMET', 'DryGASCON', 'Elephant', 'ESTATE', 'ForkAE', 'GIFT-COFB', 'Gimli', 'Grain-128AEAD', 'HERN & HERON', 'ISAP', 'Lilliput-AE', 'Oribatida', 'PHOTON-Beetle', 'Pyjamask', 'REMUS', 'Romulus', 'SAEAES', 'Saturnin', 'Shamash & Shamashash', 'SKINNY', 'SPARKLE', 'SPIX', 'SpoC', 'Spook', 'Subterranean 2.0 ', 'SUNDAE-GIFT', 'Sycon', 'TGIF', 'TinyJambu', 'Triad', 'Xoodyak', 'Yarará and Coral']
```
