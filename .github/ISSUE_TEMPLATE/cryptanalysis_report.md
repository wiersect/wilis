---
name: Cryptanalysis Report
about: Report a cryptographic weakness, distinguisher, or side-channel finding
title: "[CRYPTANALYSIS] "
labels: security
---

## Affected Component
- [ ] `WilisPerm-384` (core permutation)
- [ ] `WilisAEAD` (duplex sponge AEAD)
- [ ] `WilisKDF` v2 (hybrid memory-hard KDF)
- [ ] `WilisHash-256`
- [ ] `WILS` v1 / v2 container or streaming format
- [ ] Constant-time / side-channel / memory zeroization

## Technical Analysis
Describe the mathematical model, attack complexity (time / memory / data), or side-channel vector.

## Proof of Concept / Reproducer
Provide a minimal Rust test or script demonstrating the finding.
