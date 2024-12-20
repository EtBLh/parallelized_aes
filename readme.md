# Parallelized AES-CTR Encryption

Proof of Concepts of Parallelized AES-128 Encryption in CTR mode, the fastest approch can have 150x speed up over software-based serial implementation

## Requirements

- x86 CPU that support AES-NI, AVX512 and VAES
- GCC
- 

## Approches

- Pthread
- OpenMP
- CUDA
- AES-NI (Serial)
- AES-NI + Pthread
- VAES
- VAES + pthread

## performance
