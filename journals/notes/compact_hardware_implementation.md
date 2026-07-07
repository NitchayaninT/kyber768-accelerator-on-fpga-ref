# Summary: "A Compact Hardware Implementation of CCA-Secure Key Exchange Mechanism CRYSTALS-KYBER on FPGA"

**Authors:** Yufei Xing and Shuguo Li (Institute of Microelectronics, Tsinghua University)
**Venue:** IACR TCHES 2021, Issue 2, pp. 328–356

## Goal

Present a fully standalone, hand-coded (not HLS, not RISC-V/ARM-based) hardware
implementation of CRYSTALS-Kyber (a Module-LWE based KEM, NIST PQC 3rd-round
finalist) that supports all three security levels (k=2,3,4) and fits on the
*smallest* Xilinx Artix-7 device (XA7A12), while remaining CCA-secure via the
Fujisaki-Okamoto transform.

## Key Ideas / Contributions

1. **Unified butterfly units for NTT/INTT/PWM.** Kyber's ring `X^256+1` only
   factors into degree-2 polynomials (not degree-1, since there's no 2n-th
   root of unity), so its NTT splits into two independent 128-point classic
   NTTs (even/odd coefficients). The paper builds one butterfly datapath that
   can be reconfigured (via a 10-bit control code) to perform: standard NTT
   (DIT), INTT (DIF), and the two cycles of point-wise multiplication (PWM0/PWM1)
   needed because PWM in Kyber requires a degree-1 polynomial product mod
   `X^2 - ζ^(2br(i)+1)`, not a single field multiplication. Karatsuba is
   applied to cut this PWM from 5 multiplications down to 4.
2. **Extra absorbed operations.** The same butterfly hardware is further
   extended to absorb: the `+e'` addition at the end of INTT (mode `INTTm`),
   and the noise-addition/compression steps (`COMPs`/`DECOMP`) needed for
   ciphertext compression — saving dedicated adder hardware and cycles.
3. **Modified Barrett reduction** tailored to Kyber's fixed q=3329, replacing
   the two generic multiplications with shifts/adds, and producing the
   quotient as a side output (reused directly by the Compress operation).
4. **RAM structure for NTT.** Even/odd coefficient pairs are stored in two
   banks so both feed the two butterfly units per cycle with twiddle factors
   read only once; strict in-place computation avoids extra bit-reversal
   passes.
5. **Encode/Decode via shift registers** instead of long buffers, handling
   the mismatch between the 32-bit transmission word width and Kyber's
   variable per-coefficient bit widths (12 bits for `t̂`, `d_u`/`d_v` bits for
   ciphertext parts) with much less register overhead than prior long-buffer
   designs (~52 bits vs 352 bits).
6. **Keccak/hash module** implements SHAKE-128/256, SHA3-256/512 with one
   shared Keccak-f[1600] core (25 of 79 cycles/round used for actual hashing,
   rest for I/O), driven by a **predefined order/endpoint table** that
   schedules interleaved uniform (matrix A) and centered-binomial (noise)
   sampling from the same XOF/PRF stream — enabling a "just-in-time" sampling
   schedule that overlaps with NTT computation so almost no extra cycles are
   spent on sampling.
7. **Minimal memory footprint.** Careful reuse of RAM/FIFO blocks across
   phases (e.g., re-encryption during decapsulation reuses the FIFOs that
   held `c1,c2,t̂` from earlier phases instead of allocating new RAM), and all
   memories sized just large enough for worst-case rate mismatches between
   producer/consumer stages.
8. **Constant-time.** Except for the (public, not secret-dependent) rejection
   sampling for matrix A, the whole design runs in constant time regardless
   of input, so it resists timing attacks.

## Results (Xilinx XC7A12TCPG238-1, Vivado 2017.3)

- Critical path: 6.2 ns / 6.0 ns (server/client) → ~161/167 MHz max frequency.
- Cycle counts (server) for keygen/encaps/decaps:
  - k=2: 3768 / 5079 / 6668 cycles → 23.4 / 30.5 / 41.3 µs
  - k=3: 6316 / 7925 / 10049 cycles → 39.2 / 47.6 / 62.3 µs
  - k=4: 9380 / 11321 / 13908 cycles → 58.2 / 67.9 / 86.2 µs
- Resources (server/client): 7412/6785 LUTs, 4644/3981 FFs, 2126/1899 slices,
  2/2 DSPs, 3/3 BRAMs — fits comfortably in the smallest Artix-7 part
  (8000 LUTs / 16000 FFs / 20 BRAMs / 40 DSPs available).
- Hash core (mostly the Keccak core) is the largest resource consumer
  (>40% LUTs, ~35% FFs), followed by the NTT core.

## Comparison to Prior Work (Table 5)

- ~2× slower in cycle count but far smaller than [DFA+20] (pure-HW Kyber,
  more DSPs/BRAMs/FFs, higher frequency).
- ~10× fewer cycles and >10–40× less LUT/FF usage than [HHLW20] (another pure
  hardware Kyber implementation).
- Hundreds of times faster than RISC-V/vector-coprocessor-based designs
  ([BUC19], [FSS20], [AEL+20]) which trade area flexibility for much lower
  clock speed and higher latency.
- Faster than an HLS-based Kyber implementation ([BSNK19]), consistent with
  the general expectation that HLS underperforms hand-written RTL.
- Compared to a similar hand-coded implementation of **Saber** ([RB20], a
  Module-LWR KEM that avoids NTT via 256 parallel MAC units instead), this
  design is close in speed but uses ~3× fewer LUTs and ~2× fewer FFs — Saber
  needs no DSPs since its noise range allows shift/add multiplication, but
  its area is larger due to full parallelism.

## Conclusion

Demonstrates that a fully bespoke (no soft/hard CPU core) hardware Kyber
implementation, built around two shared, heavily-multiplexed butterfly units
and a single shared Keccak core with careful sampling/computation scheduling,
achieves markedly better area-time efficiency than both HLS-based and
hardware/software co-design approaches, while fitting into the smallest
Artix-7 FPGA and remaining constant-time/CCA-secure.
