# Caligo

Caligo is a C++ library that implements various cryptographic primitives in a C++(20)-friendly interface, while doing the utmost best to defaulting to secure, side-channel free and fast cryptography.

License: BSD-2-Clause


## Installation

Retrieve the repository and build it with an Evoke-compatible build tool. For tests, it uses Catch, while for benchmarking it uses Google benchmark. 

## Usage

TBD

## Multithreading

No global state exists, no shared state exists. No structures can be shared by multiple threads, but for any structure, two independent copies or instances can be used by independent threads.

## Cryptographic note

The intent of the library is to be a modern-day implementation of cryptography. As such, the following rules apply:

- Primitives need to be in active use by a current-day protocol. If they drop out of use, they will be removed. This is expected. If you need an old primitive, realize that you're causing a security problem.
- All implementations are expected to be and remain side-channel free, insofar as any of these side-channels could expose private information. If a side-channel is found it should be removed as soon as possible, and publicized where relevant.
- There is *zero* configuration. It should compile for the compiler-selected platform with its standard libraries. Many of the problems with security is that to set up a secure HTTPS server on OpenSSL or similar, you need a PhD in configuring the libraries.
- This library does not go for utmost performance or hardware acceleration support. It will try to get fast results, but not sacrifice readability and maintainability of the code for that. Security code should be readable so that we can be sure it's free of effects.

## License

The library is available under the (BSD 2-clause license)[https://opensource.org/licenses/BSD-2-Clause]:

Copyright 2021 Peter Bindels

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
