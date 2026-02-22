# Bloom Filter Generator
Allows the creation of a bloom filter based on a data set.

Also allows checking if an address is in the filter.


The input data set should be `\n` delineated `.txt` file that looks something like:
```
firstaddress
secondaddress
thirdaddress
```

The resulting bloom filter can be "checked against" with an address, and will respond whether that address exists in the bloom filter set or not.

It's important to keep in mind that bloom filters are probabilistic data structures and as such result in false positives at a certain rate, which can be adjusted for by increasing the data set size. Adjust this depending on your workload. If you check millions or billions or addresses against a filter and cannot tolerate more than a few false positives, we recommend setting an appropriately small false positive factor.

If you have lots of unused RAM capacity in which you can store the original data set, the overhead and size-accuracy trade-offs of a bloom filter may not be necessary for you.

## Generate bloom filter
`python bloom-util.py create --filter_file filter.pkl --addresses_file addresses.txt`

## Check if address is in bloom filter
`python bloom-util.py check --filter_file filter.pkl --address firstaddress`

$ Address firstaddress is in the filter

`python bloom-util.py check --filter_file filter.pkl --address fourthaddress`

$ Address fourthaddress is not in the filter

## Status

This is experimental, unmaintained code. Use only as research inspiration.

Specifically, we make no security guarantees.
Deserializing malicious filters may be problematic, for example.

## License

Licensed under either of `Apache License, Version 2.0` or `MIT` license at your option.

## Credits

Written by Anton Livaja, improved by Christian Reitter.