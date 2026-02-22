# Address Checks using a Bloom Filter

This tool checks addresses against a bloom filter.
We used it as part of our early research while experimenting with address generation, bloom filters,
and sourcing lists of known addresses.

We use a custom binary serialization format for the bloom filter objects because the `bloomfilter` version `1.x` does not implement its own function for this purpose. The newer `bloomfilter` `3.x` version as well as other bloom filter crates do provide serialization and deserialization functions, so we recommend using one of those instead for new projects.

## Usage

See the application `--help` output.

## License

Licensed under either of `Apache License, Version 2.0` or `MIT` license at your option.

## Credits

Written by Heiko Schaefer, with some improvements by Christian Reitter.