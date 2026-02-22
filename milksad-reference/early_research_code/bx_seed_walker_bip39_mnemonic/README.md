# bx seed walker for BIP39 mnemonics

Optimized proof-of-concept program to derive all possible `2^32` weak mnemonics for `CVE-2023-39910` on a given key length without the need for slow `bx` calls.

Basic operation:
* Walk over all possible PRNG seeding states
* For each PRNG configuration:
  * simulate the `bx seed` behavior to derive the corresponding weak seed
  * simulate `bx mnemonic-new` to construct a BIP39 mnemonic
  * output the resulting data on stdout

This program does not perform any filtering of the recovered mnemonics by any criteria.

With some modifications to the PRNG consumption pattern, this program should also be able to generate mnemonics for `CVE-2023-31290`, although we didn't test this.

## Usage

* Build: see `Makefile`.
* Parameters set at build time using build variables.
* Output to stdout.
* Warning: when directed to the file system, the output files for a complete key range will be large (several 100 GiB).

## Status

This is experimental, unmaintained code. Use only as research inspiration.

This program was helpful as a quick proof-of-concept implementation during early experimentation and research in July 2023. It remains in an experimental state.

## License

This folder contains adapted code from multiple sources, as well as derived code. See the file headers for more information.

Due to the derivative usage of libbitcoin code, the primary license is `GNU Affero General Public License` in version 3 or later.

Other code snippets fall under different licenses, namely some versions of CC BY SA.

## Credits

Written by Christian Reitter. Based on code from libbitcoin and other authors.

## Tests

Example to compare output with stock `bx` behavior for a given `FAKETIME` value == PRNG seed id:
```
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME_FMT=%s FAKETIME=4.294967294 ./bx-linux-x64-qrcode seed -b 256 | ./bx-linux-x64-qrcode mnemonic-new
```
