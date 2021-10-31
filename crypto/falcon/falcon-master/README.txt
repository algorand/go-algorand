FALCON IMPLEMENTATION
=====================

Version: 2020-09-30

Falcon is a post-quantum signature algorithm, submitted to NIST's
Post-Quantum Cryptography project:

   https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

Falcon is based on NTRU lattices, used with a hash-and-sign structure
and a Fourier-based sampling method that allows efficient signature
generation and verification, while producing and using relatively
compact signatures and public keys. The official Falcon Web site is:

   https://falcon-sign.info/


This implementation is written in C and is configurable at compile-time
through macros which are documented in config.h; each macro is a boolean
option and can be enabled or disabled in config.h and/or as a
command-line parameter to the compiler. Several implementation strategies
are available; however, in all cases, the same API is implemented.

Main options are the following:

  - FALCON_FPNATIVE and FALCON_FPEMU

    If using FALCON_FPNATIVE, then the C 'double' type is used for all
    floating-point operations. This is the default. This requires the
    'double' type to implement IEEE-754 semantics, in particular
    rounding to the exact precision of the 'binary64' type (i.e. "53
    bits"). The Falcon implementation takes special steps to ensure
    these properties on most common architectures. When using this
    engine, the code _may_ need to call the standard library function
    sqrt() (depending on the local architecture), which may in turn
    require linking with a specific library (e.g. adding '-lm' to the
    link command on Unix-like systems).

    FALCON_FPEMU does not use the C 'double' type, but instead works
    over only 64-bit integers and embeds its own emulation of IEEE-754
    operations. This is slower but portable, since it will work on any
    machine with a C99-compliant compiler.

  - FALCON_AVX2 and FALCON_FMA

    FALCON_AVX2, when enabled, activates the use of AVX2 compiler
    intrinsics. This works only on x86 CPU that offer AVX2 opcodes.
    Use of AVX2 improves performance. FALCON_AVX2 has no effect if
    FALCON_FPEMU is used.

    FALCON_FMA further enables the use for FMA ("fused multiply-add")
    compiler intrinsics for an extra boost to performance. This
    setting is ignored unless FALCON_FPNATIVE and FALCON_AVX2 are
    both used. Occasionally (but rarely), use of FALCON_FMA will
    change the keys and/or signatures generated from a given random
    seed, impacting reproducibility of test vectors; however, this
    has no bearing on the security of normal usage.

  - FALCON_ASM_CORTEXM4

    When enabled, inline assembly routines for FP emulation and SHAKE256
    will be used. This will work only on the ARM Cortex M3, M4 and
    compatible CPU. This assembly code is constant-time on the M4, and
    about twice faster than the generic C code used by FALCON_FPEMU.


USAGE
-----

See the Makefile for compilation flags, and config.h for configurable
options. Type 'make' to compile: this will generate two binaries called
'test_falcon' and 'speed'. 'test_falcon' runs unit tests to verify that
everything computes the expected values. 'speed' runs performance
benchmarks on Falcon-256, Falcon-512 and Falcon-1024 (Falcon-256 is a
reduced version that is faster and smaller than Falcon-512, but provides
only reduced security, and not part of the "official" Falcon).

Applications that want to use Falcon normally work on the external API,
which is documented in the "falcon.h" file. This is the only file that
an external application needs to use.

For research purposes, the inner API is documented in "inner.h". This
API gives access to many internal functions that perform some elementary
operations used in Falcon. That API also has some non-obvious
requirements, such as alignment on temporary buffers, or the need to
adjust FPU precision on 32-bit x86 systems.


LICENSE
-------

This code is provided under the MIT license:

==========================(LICENSE BEGIN)============================
Copyright (c) 2017-2020  Falcon Project

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
===========================(LICENSE END)=============================

The code was written by Thomas Pornin <thomas.pornin@nccgroup.com>, to
whom questions may be addressed. I'll endeavour to respond more or less
promptly.
