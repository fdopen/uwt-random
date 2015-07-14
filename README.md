Uwt_random

C stub for [uwt](https://github.com/fdopen/uwt). Obtain random data
from your OS.

* Windows:
 * CryptGenRandom

* Linux:
 * sycall with SYS_getrandom (kernel 3.17 or newer)}
 * /dev/urandom (will fail inside chroots or if you are out of file descriptors)
 * a deprecated SYS__sysctl syscall

* Freebsd
 * dedicated syscall
 * /dev/urandom (usually a link to /dev/random)
 * /dev/random (doesn't block)

* Netbsd
 * dedicated syscall
 * /dev/urandom

* Openbsd
 * getentropy
 * /dev/urandom

* Sun
 * /devices/pseudo/random@0:urandom
 * /dev/urandom

* All other systems
 * /dev/urandom


## Installation

Dependencies:

* OCaml 4.02.1 (earlier versions are not supported)
* libuv 1.0 or later (0.x versions are not supported)
* [uwt](https://github.com/fdopen/uwt)
* optional:  [nocrypto](https://github.com/mirleft/ocaml-nocrypto)

Build dependencies:

* autoconf
* pkg-config / pkgconf
* findlib
* omake
* ounit

```
$ omake all
$ omake install
```
