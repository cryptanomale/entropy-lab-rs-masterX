# Finding Weak "brain wallets"

This tool checks if any of the text snippets from the input were used as passphrases for a brain wallet. For now, this search is Bitcoin-only. It uses multi-threading by default.

The use of brain wallets was a dangerous practice in the first years of Bitcoin, and is extremely vulnerable to brute-forcing. See other code and documentation such as https://git.distrust.co/milksad/rust-bloom-filter-generator and https://milksad.info/posts/research-update-3/ on how to obtain the necessary Bitcoin address lists and generate the bloom filter that identifies used addresses.

## Usage

See the application `--help` output.

To manually override the number of parallel rayon threads, use the environment variable `RAYON_NUM_THREADS` such as `RAYON_NUM_THREADS=23`.

## Status

This repository contains unmaintained and unstable code which is meant for other researchers. We give no functionality or security guarantees.

Feedback is welcome, but we're unlikely to implement any feature requests.

## Research Ethics and Prior Work

This code finds weak private keys. The code author(s) ask you to remember that with great power comes great responsibility. See also [here](https://github.com/ryancdotorg/brainflayer?tab=readme-ov-file#disclaimer).

In-depth security research on this exact topic, such as [Ryan Castellucci's DEFCON23 talk](https://rya.nc/defcon-brainwallets.html) and [brainflayer](https://github.com/ryancdotorg/brainflayer) tool has been public and widely known for over **ten years** at this point. Clearly, more efficient and versatile tooling than our  code was already published. We therefore think the educational and scientific benefits of making our code public outweigh the risks.

## Usage Warning

Parallel CPU brute forcing of hashes and cryptocurrency keys causes exceptionally high CPU load and high temperatures, which some systems may not be able to handle. Ensure that your machine can deal with such workloads, for example by running CPU-intensive benchmark tools for multiple hours while monitoring temperatures.

Use this code at your own risk. You've been warned.

## License

To be determined.

## Credits

Written by Christian Reitter.