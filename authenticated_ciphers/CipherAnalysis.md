Cipher Analysis
================================================================================

Task: Check all the ciphers currently in the `authenticated_ciphers` module of FELICS and check whether they were correctly implemented and if the FELICS API is adequate for the ciphers.

## Framework and API notes
- Ketje-Sr should be implemented together with Ketje-Jr.
- There could be a default `indent.pro` to be used on the whole project, to keep the files neat and consistent with each other.
- Implement ASCON-128a
- Define endianness change routines for all ciphers, using optimized code for each architecture, to be used by the implementors.
- The framework could define a default and optimized implementation of AES and AES functions for the authenticated algorithms that use it, in the same way as SUPERCOP does.
- MORUS-640-128 (secondary recommendation in the CAESAR submission) is listed as a UseCase1 cipher, could be added to the framework.
- There needs to be an implementation of FOM for AEAD


--------------------------------------------------------------------------------

## ACORN
Johann will be the one working on the implementation of this cipher.

### Details of the cipher
- C only implementation on both version, there are no optimizations specific for the target architectures, even in C.
- There are two boolean function used in ACORN: $\text{maj}(xyz) = (x \& y) \oplus (x \& z) \oplus (y \& z)$ and $\text{ch}(xyz) = (x \& y) \oplus (\neg x \& z)$. Both are in minimal form already, but is necessary, the second can be rewritten without the negation as $\text{ch}(xyz) = (x \& y) \oplus (x \& z) \oplus z$.
- The cipher uses a 128-bit key and a 128-bit IV. Authentication tag is also 128-bit or less.
- The internal state is 293-bits long and updated with six concatenated LSFRs. The update function consists  of three main steps:
    1. Update of the internal state using 6 LFSRs.
    2. Calculation of the keystream bit and non-linear feedback bit.
    3. Shift the 293-bit register with the feedback bit $f_i$.
- The initialization of Acorn consists in loading the key and IV into the state and running the cipher for **1792 steps**.
- When there is no AdditionalData, the state is still updated for 256 steps.
- When there is no Ciphertext, the state is still updated for 256 steps.
- The authors fo the cipher empathize that, if verification of the tag fails, ciphertext and the calculated authentication tag should not be returned as outputs, since that could make the internal state of the ACORN prone to *Known Plaintext Attacks* and *Chosen Plaintext Attacks*, using a fixed IV.
- ACORN allows parallel computations, with 32 steps being computed in parallel, what allows good speed in software implementations, although the main design focus of ACORN is hardware efficiency.
- The step function has a direct map from bit to byte, what makes the "8-step" parallel implementation straightforward. The "32-step" parallel implementation, on the other hand, is simply a mapping of the bit transformation to a 4fold iteration of the 8-step one. Therefore, one could not make much use of ARM's 32-bit registers for it, as there are overlaps between the 8-bit indexes.
- For v01, bit layout is simple bit packing.
```
┏──────┓   ┏──────┓   ┏──────┓       ┏──────┓
|  00  |   |  01  |   |  02  |  ...  |  n   |
┗──────┛   ┗──────┛   ┗──────┛       ┗──────┛
0      7   8     15   16    23           8n━1
```

### Implementation Analysis
- v01 is the ACORN implementation with 32bits of state processed at the same time, while v02 is optimized for less RAM and ROM usage.
- Blocksize is 4 bytes in v01, and 1 byte in v02
- State size is defined as {41, 38} bytes. Could it be done with 36 bytes?
- No 'finalize' function defined in 'finalize.c' for both versions.
- In `initialize.c`, the key and nonce are added into the state via calls to the `acorn128_32steps`. The reference code defines the initialization as setting the first 36 bytes of the state with the state and key, then updating the state 244 times. It seems to make sense since 244 calls to the 8 step function are unavoidable in the init. For ARM, it would be wise to use the 32step function, making use of the whole 32-bit registers, if possible.
- There are inconsistencies in the loops between the use of `i++` and `i=i+1`.
- There is no clear indicator of the state layout in memory.
- `permute.c:acorn128_32steps` in v01 has a small AVR optimization, but I believe it is something that `gcc` can do it automagically.
- The internal state is initialized with {1,4} more bytes than the necessary to hold the defined 293bits of the internal state (already taking into account the three unused bits in `state[37]` )

#### Implementation Characteristics
- [ ] C implementation
- [ ] ARM optimizations
- [ ] ARM assembler code
- [x] AVR optimizations
- [ ] AVR assembler code
- [ ] MSP optimizations
- [ ] MSP assembler code


### Issues
- [ ] v01 `initialize.c:40` The loop is written in a strange way. Why?
- [ ] Why the need for a single iteration loop at `initialize.c:58`  ? Also, the loop bounds, at least the one to zero the cipher should use macros.
- [ ] `padding.c` Seems to implement a misnomer. The padding itself does not execute a plaintext/ciphertext/ad padding but instead implements the 256-step domain separation.
- [ ] Comment the code, how the layout of the state is in memory.
- [ ] The permutation function does a lot of bit manipulation. Would there be a way to pack data into the 8bit registers in such a way that these bit manipulations are avoided?
- [ ] On the loops for the v01, the loop bounds should have an explanation. For example, the loop `for (i = 0; i < (associated_data_length & 0xfc); i = i + 4)` in `process_associated_data.c` is not self explanatory at first sight.
- [ ] Why the is there these two different implementations of `acorn128_8steps`?
    On the v01 version:
    ```c
    if (enc_dec_flag == 1)
        *ciphertextbyte = *plaintextbyte ^ ksbyte;
    else
        *plaintextbyte = *ciphertextbyte ^ ksbyte;
    ```
    Versus this on the v02 version:
    ```c
    if (enc_dec_flag == 1)
        *(ciphertextbyte) = *(plaintextbyte) ^ ksbyte;
    else
        if (enc_dec_flag == 0)
            *(plaintextbyte) = *(ciphertextbyte) ^ ksbyte;
    ```
- [ ] In v01's `process_plaintext.c` is the best way to execute a 4byte encryption?
    ```c
    acorn128_32steps(state, (message + i), ciphertextByte, 0xff, 0, 1);
    *((uint32_t *)&message[i]) = *(uint32_t *)ciphertextByte;
    ```
- [ ] Why test0 in `test_vectors` are different? And why the state size is different from one implementation to the other?
<!---
- [ ] in `permute.c`, there is a `uint8_t *plaintextbyte` and `uint8_t *ciphertextbyte`. This function should be rewritten in a way as to not use an `if` statement..
-->


### Testing
- [x] Compilation v01 (ARM, AVR, MSP, PC)
- [x] Test vectors v01 (ARM, AVR, MSP, PC)
- [ ] Compilation v02
    - Warning:
    ```
    process_ciphertext.c: In function ‘ProcessCiphertext’:
    process_ciphertext.c:39:16: warning: unused variable ‘j’ [-Wunused-variable]
     uint8_t i, j;
                ^
    ```
- [ ] Test vectors v02
    - AVR:
    ```
    O:CORRECT!
    O:->Encryption initialization begin
    CORE: *** Invalid read address PC=09ac SP=1065 O=8180 Address 1100 out of ram (10ff)
    avr_sadly_crashed
    ```
    - ARM/MSP/PC: Cipher is self-contained, but the intermediate states do not match. It is necessary to use the reference implementation to generate intermediate values and match them with the cipher; fix the implementation accordingly.


### Testing
- [x] Compilation v01 (ARM, AVR, MSP, PC)
- [x] Test vectors v01 (ARM, AVR, MSP, PC)
- [ ] Compilation v02
    - Warning:
    ```
    process_ciphertext.c: In function ‘ProcessCiphertext’:
    process_ciphertext.c:39:16: warning: unused variable ‘j’ [-Wunused-variable]
     uint8_t i, j;
                ^
    ```
- [ ] Test vectors v02
    - AVR:
    ```
    O:CORRECT!
    O:->Encryption initialization begin
    CORE: *** Invalid read address PC=09ac SP=1065 O=8180 Address 1100 out of ram (10ff)
    avr_sadly_crashed
    ```
    - ARM/MSP/PC: Cipher is self-contained, but the intermediate states do not match. It is necessary to use the reference implementation to generate intermediate values and match them with the cipher; fix the implementation accordingly.

--------------------------------------------------------------------------------

## AES GCM

### Details of the cipher
- V01: AES-GCM 128-bits, IV 96 bits. V02 is the same, but with constants stored in RAM

### Implementation Analysis
- [x] `rc_tab` and `sbox` should be defined in `constants.c` file.

#### Implementation Characteristics
- [ ] C implementation
- [ ] ARM optimizations
- [ ] ARM assembler code
- [ ] AVR optimizations
- [ ] AVR assembler code
- [x] MSP optimizations
- [ ] MSP assembler code

### Testing
- [x] Compilation
    - v01
        ```
        tag_generation.c: In function ‘TagGeneration’:
        tag_generation.c:67:5: warning: implicit declaration of function ‘mul_h’ [-Wimplicit-function-declaration]
             mul_h(gcm_state->H, t, tag);
        ```
- [ ] Test vectors
    - The output of the cipher is strange, lacking traces of the internal state in the functions. Maybe it is a framework issue, due to the use of a struct to represent the internal state instead of the default `uint8_t[]`.


--------------------------------------------------------------------------------

## ASCON

### Details of the cipher
- ASCON uses a sponge-based mode of operation with a recommended key, tag and nonce lengths of 128 bits. The sponge operates over an internal state of 128-bits. The sponge operates over an internal state of 320bits and operates over blocks of 64 or 128 bits of data. The core of ASCON iteratively applies an SPN-based round function with a bit-sliced 5-bit SBox.

#### Implementation Characteristics
- [ ] C implementation
- [ ] ARM optimizations
- [ ] ARM assembler code
- [ ] AVR optimizations
- [ ] AVR assembler code
- [x] MSP optimizations
    - Not that much, just some preprocessing macros for the Aarch.
- [ ] MSP assembler code

### Issues
- [ ] ASCON-128a, the version that operates over 128-bit blocks could also be implemented on the framework.
- [x] In `Initialize`, the sponge should be initialized with constants or defines, not magic numbers.
- [ ] Could use other methods for changing endianness, optimized for each architecture. These methods could be part of the Framework, to be used by the other ciphers.
- [ ] The sponge is represented in little-endian, and the endianness of the whole sponge is changed to big and back before each application of the permutation. It would be better to, instead, change the endianness of the plaintext/ciphertext/ad and keep the internal state in the big-endian representation. Uses 80% fewer endianness swaps that way.


### Testing
- [x] Compilation
- [x] Test vectors

--------------------------------------------------------------------------------

## Ketje-Jr

### Details of the cipher
- Ketje is a set of four AEAD algorithms, aimed at memory constrained devices and that relies strongly on nonce uniqueness for its security. The algorithm is built over a round-reduced version of Keccak-$f$.
- Ketje uses the MonkeyDuplex construction over the MonkeyWrap mode of operation.
- the two smaller instances of Ketje are called Jr and Sr, while the larger instances are called Ketje Minor an Major. The permutation width is {200, 400, 800, 1600} bits.
- Keccak-p is defined by a parameter $b=25 \times 2^\ell$. When the number of rounds $n_r  = 12 + 2\ell$, then $\text{keccak-p}[b, n_r]=\text{keccak-}f[b]$.
- A round of Keccak-p is composed of five steps: $R = \tau \circ \chi \circ \pi \circ \rho \circ \theta$
- Regarding the smaller instances of Ketje, Jr has a security level of 96bits and Sr has a security level of 128bits. Jr has such a smaller security level due to its thin 200-bit permutation, as it would impose too many limitations in the cipher's complexity.
- Regarding security, Ketje features the generic security of the MonkeyWrap mode and the security assurance from the cryptanalysis of Keccak. Due to the Matryoshka property, most of the analysis performed on the full-width permutation are transferable to the smaller widths version. The cipher also has good characteristics in relation to side channel protection, both in hardware and software implementations.
- All instances of Ketje (except Major) are considered lightweight.
- Ketje-Jr has a 25-byte state and a 2-byte block size. `Init` takes 12 rounds and Tag generation takes 9 rounds.

#### Implementation Characteristics
- [x] C implementation
- [ ] ARM optimizations
- [ ] ARM assembler code
- [ ] AVR optimizations
- [ ] AVR assembler code
- [ ] MSP optimizations
- [ ] MSP assembler code

### Issues
- [ ] The algorithm implemented is Ketje-Jr. In the Ketje paper, Ketje-Sr is the one defined as the primary recommendation. As such, it should be added to the framework.

- [x] I think I'll leave it this way, on second thought. It seems to be organized and follow a reference code.
    > There are too many scattered .c files, they could be added together into a `functions.c` and `functions.h` file. There don't seem to be any real use for keeping all those functions in different files.
- [x] `KeccakP200_AddBytes` does unnecessary bound validation. Since these functions are not top level, it could be omitted, instead relying on the code being correct.
- [x] `KeccakP200_Permute_Nrounds()` has a single call to `KeccakP200OnWords`, which has n calls to `KeccakP200Round`, which by itself only wraps $\tau$, $\chi$, $\pi$, $\rho$, and $\theta$. I see this as unnecessary, maybe the function should be refactored on that point and turn it into a single function (all in file `keccak_round.c`).
- [x] The constants should be put into a `constants.c` file (resulting in the removal of `KeccakRhoOffsets.c`, `keccakRoundConstants.c`, `KetJr_StateTwistIndexes.c`)
- [x] Maybe no, since GCC most probably optimizes this out.
    > Wrapping functions --example below-- could be replaced with macros.
    >    ```c
    >    void KetJr_StateAddByte( uint8_t *state, uint8_t value, unsigned int offset )
    >    {
    >        KeccakP200_AddByte(state, value,
    >            READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[offset / Ketje_LaneSize])*
    >            Ketje_LaneSize + offset % Ketje_LaneSize);
    >    }
    >
    >    ```
- [x] The implementation of `KeccakP200_Permute_Nrounds` is not consistent between the two versions of Ketje-Jr.
    > The `if` in `KetJr_StateExtractByte` (v02) is always true.
- [x] The `if` statement in `KetJr_Step` (v02) is always true.
- [x] The `if` statement in `KetJr_UnwrapBlocks`is always true. This construction seems to happen quite a bit in the code. I wonder if there is any reason behind it that is out of my grasp. `if(READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE]) < 25)` KetJr_StateTwistIndexes has no elements with value greater equal than 25. Instrumenting this code and checking if these `if` s are ever false is necessary.

### Testing
- [X] Compilation
- [X] Test vectors


--------------------------------------------------------------------------------
## NORX

### Details of the cipher
- Norx is a novel authenticated encryption scheme supporting an arbitrary parallelism degree. it is based on ARX primitives, yet it does not use modular addition.
- Norx is parametrized by the word size $w \in \{32.64\}$ bits; a round number $1 \leq \ell \leq 63$; a parallelism degree $0 \leq p \leq 255$ and a tag size of $t \leq 4w$.
- Differences from Norx2.0 to Norx3.0:
    - Nonce size increased from $2w$ to $4w$.
    - Additional XOR of the key in init and finalize functions.
    - The tag is extracted from the sponge capacity instead of the sponge rate.

### Implementation Analysis
- The implemented algorithms are:

| FELICS name                 | NORX Instance|
|-----------------------------|--------------|
|NORX_384_128_128_512_128_v01 |      NORX3241|
|NORX_384_128_128_512_128_v02 |      NORX3261|
|NORX_384_128_128_512_128_v03 |      NORX3241|
|NORX_384_128_128_512_128_v04 |      NORX3261|

#### Implementation Characteristics
- [x] C implementation
- [x] ARM optimizations (32bit opt C code)
- [ ] ARM assembler code
- [ ] AVR optimizations
- [ ] AVR assembler code
- [ ] MSP optimizations
- [ ] MSP assembler code

### Issues
- [ ] As it was the case with previous ciphers, there is no need to divide one `*.c` file for each function.
- [x] In function `Finalize` there are two shifting loops that don`t exist in the original implementation. Those are not needed for manipulating the internal states.
    - But modifying it would result in rewriting a lot of code. V03 and V04 will solve this issue.
- [x] Data types are specified in the wrong file. Types are in `norx.h`, should be in `data_types.h`
- [x] In initialize, there is no need to manipulate data of type `norx_state_t`
    - Actually, it is necessary for V01 and V02 due to the way that the rest of the algorithm was implemented. V03 and V04 don't need it.
- [x] There is no need for Norx code with `P!=1`, but maybe it should be kept as an example since they are fenced in a `#ifdef` statement.
- [x] There is no need for that big expression in `TagGeneration`, just use `tag[i]=state[const+i];`
    - I changed my mind here since the compiler will probably calculate it on the fly, and it is a nice interpretation of the logic behind the tag extraction (the tag is extracted from the end of the sponge.)
- [ ] Test vectors don't match the test vectors in the Norx specification.

### Testing
- [x] Compilation
- [x] Test vectors
