# Wilis Cryptographic Specification (v0.2.0)

This document defines the exact mathematical construction and binary container wire formats of the **Wilis** cryptographic suite.

---

## 1. Core Permutation: `WilisPerm-384`

### 1.1 State Layout
The internal state $S$ consists of **384 bits** organized as six 64-bit unsigned little-endian words:

$$S = (w_0, w_1, w_2, w_3, w_4, w_5) \in (\mathbb{Z}_{2^{64}})^6$$

- **Rate ($r = 128$ bits / 16 bytes):** $(w_0, w_1)$
- **Capacity ($c = 256$ bits / 32 bytes):** $(w_2, w_3, w_4, w_5)$

### 1.2 Round Constants
There are 32 distinct 64-bit round constants $RC_0, \dots, RC_{31}$ defined transparently from the first 32 prime numbers $p_i$:

$$RC_i = \left\lfloor 2^{64} \cdot \left( p_i^{1/5} - \lfloor p_i^{1/5} \rfloor \right) \right\rfloor, \quad i \in \{0, \dots, 31\}$$

For a call executing $R \in \{1, \dots, 16\}$ rounds, the round index iterates $r = (16 - R), \dots, 15$. Standard round counts are:
- **$R_{\text{full}} = 16$:** Initialization, finalization, KDF setup/squeeze, hash finalization.
- **$R_{\text{data}} = 12$:** AAD absorption, duplex message encryption/decryption, KDF memory sweeps.

### 1.3 Round Function
Each round $r$ applies five strictly bijective sub-layers in order:

1. **Asymmetric Constant Injection**
   $$w_0 \leftarrow w_0 \oplus RC_{2r}, \qquad w_3 \leftarrow (w_3 + RC_{2r+1}) \bmod 2^{64}$$

2. **Primary ARX Mixing**
   Define the invertible 2-word ARX gadget $\mathrm{ARX}(a, b; r_1, r_2)$:
   ```text
   a = (a + b) mod 2^64
   b = rotl64(b, r1) ^ a
   a = (a + b) mod 2^64
   b = rotl64(b, r2) ^ a
   ```
   Applied in parallel to three disjoint pairs:
   - $\mathrm{ARX}(w_0, w_1; 13, 37)$
   - $\mathrm{ARX}(w_2, w_3; 19, 43)$
   - $\mathrm{ARX}(w_4, w_5; 29, 53)$

3. **Bitsliced Nonlinear Substitution (`Chi-5` + `Feistel-6`)**
   - Compute 5-word `Chi` simultaneously across all 64 bit-slices:
     $$w'_i = w_i \oplus (\neg w_{(i+1) \bmod 5} \land w_{(i+2) \bmod 5}), \quad i \in \{0, 1, 2, 3, 4\}$$
   - Update $w_5$ via nonlinear Feistel mixing from the updated $w'_{0..4}$:
     $$w'_5 = w_5 \oplus (w'_0 \land w'_2) \oplus (w'_1 \land w'_4) \oplus \mathrm{rotl}_{64}(w'_3, 7)$$

4. **Staggered Cross-Word ARX Mixing**
   - $\mathrm{ARX}(w_1, w_2; 17, 41)$
   - $\mathrm{ARX}(w_3, w_4; 23, 47)$
   - $\mathrm{ARX}(w_5, w_0; 31, 59)$

5. **Intra-Word 3-Tap Diffusion & Cyclic Lane Rotation**
   For each word $w_i$ with tap pair $(a_i, b_i) \in \{(7,29), (11,41), (17,53), (23,37), (13,47), (19,59)\}$:
   $$w_i \leftarrow w_i \oplus \mathrm{rotr}_{64}(w_i, a_i) \oplus \mathrm{rotr}_{64}(w_i, b_i)$$
   followed by cyclic left rotation of the 6 word lanes: $(w_0, w_1, w_2, w_3, w_4, w_5) \leftarrow (w_1, w_2, w_3, w_4, w_5, w_0)$.

Because every sub-layer is provably bijective (`Chi-5` has exact order 4; every 3-tap polynomial $1 + t^a + t^b$ has order dividing 64 over $\mathrm{GF}(2)[t]/(t^{64}+1)$), `WilisPerm-384` is guaranteed to be a bijection on $\{0,1\}^{384}$.

---

## 2. Domain Separators

| Phase | ASCII Tag | 64-bit Constant |
| :--- | :---: | :--- |
| AEAD Init | `WILS_INI` | `0x5749_4C53_5F49_4E49` |
| AEAD AAD | `WILS_AAD` | `0x5749_4C53_5F41_4144` |
| AEAD Message | `WILS_MSG` | `0x5749_4C53_5F4D_5347` |
| AEAD Finalize | `WILS_FIN` | `0x5749_4C53_5F46_494E` |
| KDF | `WILS_KDF` | `0x5749_4C53_5F4B_4446` |
| Hash | `WILS_HSH` | `0x5749_4C53_5F48_5348` |

---

## 3. Authenticated Encryption: `WilisAEAD`

- **Inputs:** 256-bit key $K = (k_0, k_1, k_2, k_3)$, 192-bit nonce $N = (n_0, n_1, n_2)$, arbitrary AAD $A$, arbitrary plaintext $P$.
- **Outputs:** Ciphertext $C$ ($|C| = |P|$) and 256-bit tag $T$.

1. **Initialization & Key Whitening:**
   - $S \leftarrow (\text{DOMAIN\_INIT}, k_0, k_1, k_2, k_3, n_0)$; $S \leftarrow P_{16}(S)$.
   - $w_0 \leftarrow w_0 \oplus n_1$, $w_1 \leftarrow w_1 \oplus n_2$; $S \leftarrow P_{16}(S)$.
   - $w_{2..5} \leftarrow w_{2..5} \oplus K$.
2. **AAD Absorption:**
   - $w_5 \leftarrow w_5 \oplus \text{DOMAIN\_AAD}$.
   - If $|A| > 0$: pad $A$ with `0x80 || 0x00*` to a multiple of 16 bytes; XOR each 16-byte block into rate $(w_0, w_1)$ and apply $P_{12}(S)$.
   - $w_5 \leftarrow w_5 \oplus 1$.
3. **Duplex Encryption / Decryption:**
   - $w_5 \leftarrow w_5 \oplus \text{DOMAIN\_MSG}$.
   - For each full 16-byte block: $C_i = P_i \oplus \mathrm{Rate}(S)$, set $\mathrm{Rate}(S) \leftarrow C_i$, apply $P_{12}(S)$.
   - For final partial block ($0 \le m < 16$ bytes): XOR remaining bytes against $\mathrm{Rate}(S)[0..m]$, set $\mathrm{Rate}(S)[0..m] \leftarrow C_{\text{rem}}$, and XOR `0x80` into $\mathrm{Rate}(S)[m]$.
4. **Finalization & Keyed 256-bit Tag:**
   - $w_5 \leftarrow w_5 \oplus \text{DOMAIN\_FINAL}$; $w_{2..5} \leftarrow w_{2..5} \oplus K$; $S \leftarrow P_{16}(S)$.
   - $T[0..16] = \mathrm{Rate}(S) \oplus K[0..16]$; $S \leftarrow P_{12}(S)$; $T[16..32] = \mathrm{Rate}(S) \oplus K[16..32]$.

---

## 4. Hybrid Memory-Hard KDF: `WilisKDF` v2

- Allocates a scratchpad $M$ of `memory_blocks` 384-bit states (`48 bytes` each):
  - `Interactive`: `349,520` blocks (**16 MiB**), `passes = 3`
  - `High`: `699,040` blocks (**32 MiB**), `passes = 4`
  - `Paranoid`: `1,398,080` blocks (**64 MiB**), `passes = 6`
- Absorbs `(DOMAIN_KDF ^ keyfile_flag, params, passphrase_len, salt_192, passphrase)` and optional 256-bit `WilisHash-256(keyfile)` with domain `KF_2FA`.
- **Pass 0 (Data-Independent):** Fills $M[0..L-1]$ mixing $M[i-1]$ and a deterministic non-secret index $j = f(i) \bmod i$, resisting cache-timing leakage.
- **Passes $1 \dots T-1$ (Data-Dependent):** Sweeps $M[0..L-1]$ mixing $M[i]$ and state-selected $M[(w_0 \oplus \mathrm{rotl}_{64}(w_3, 17)) \bmod L]$, defeating time-memory tradeoff attacks.
- Folds 16 strided memory slots, squeezes 256-bit `SecretKey`, and volatile-zeroizes all $L$ states.

---

## 5. Binary Container Wire Formats

### 5.1 `WILS` v1 (Single-Shot Container)
```text
Passphrase Mode (0x01) — 62-byte header:
  [ "WILS": 4B ][ ver=1: 1B ][ mode=1: 1B ][ mem_blocks: u32 LE ][ passes: u32 LE ]
  [ salt: 24B ][ nonce: 24B ][ ciphertext: N bytes ][ tag: 32B ]

Raw Key Mode (0x02) — 30-byte header:
  [ "WILS": 4B ][ ver=1: 1B ][ mode=2: 1B ][ nonce: 24B ][ ciphertext: N bytes ][ tag: 32B ]
```
Bound AAD: `header_bytes || (user_aad.len() as u64 LE) || user_aad`.

### 5.2 `WILS` v2 (Constant-Memory Chunked Streaming Container)
Appends `[ chunk_size: u32 LE ]` (default `65536`) immediately after `nonce` in the header (66B passphrase / 34B raw-key). Followed by one or more authenticated chunk frames:

```text
Chunk Frame (index = 0, 1, 2, ...):
  [ pt_len: u32 LE ][ is_final: u8 (0 or 1) ][ ciphertext: pt_len bytes ][ tag: 32B ]
```
- Per-chunk nonce: `base_nonce ^ (chunk_index LE into bytes 16..24) ^ (0xFF at byte 15 if is_final)`.
- Per-chunk AAD: `WilisHash-256(header_bytes) || chunk_index_u64_le || is_final_u8 || user_aad_len_u64_le || user_aad`.
- Decryption rejects missing `is_final = 1` (truncation), any data after `is_final = 1` (append), swapped/duplicated chunks, or any tag mismatch.
