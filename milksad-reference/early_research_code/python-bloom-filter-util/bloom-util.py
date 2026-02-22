import argparse
import hashlib
import pickle
from pybloom_live import BloomFilter
import csv
import sys

def construct_bloom_filter(addresses_file, filter_file):
    # false positive: 0.000000001 = 4 out of 4 billion
    # TODO max capacity is hardcoded
    # TODO error rate is hardcoded
    # this is a problem when using larger or significantly smaller data sets
    bloom_filter = BloomFilter(capacity=1180626779, error_rate=0.000000001)
    with open(addresses_file, 'r') as file:
        for line in file:
            address = line.strip()
            bloom_filter.add(address.encode())

    with open(filter_file, 'wb') as f:
        pickle.dump(bloom_filter, f)
    print(f'Bloom filter created and saved as {filter_file}')

def check_address(filter_file, address):
    with open(filter_file, 'rb') as f:
        bloom_filter = pickle.load(f)

    if address.encode() in bloom_filter:
        print(f'Address {address} is in the filter')
        return True
    else:
        print(f'Address {address} is not in the filter')
        return False

def check_address_csv(filter_file, address_csv_file, skip_lines = 0):
    # TODO output discovered results to another file

    with open(filter_file, 'rb') as f:
        bloom_filter = pickle.load(f)

    status_print_every = 10_000_000
    print("unpickled bloom filter file")
    sys.stdout.flush()
    i = 0
    found = 0
    skip_lines_remaining = skip_lines
    with open(address_csv_file, 'r') as file:
        csvreader = csv.reader(file, delimiter=',')
        for dataline in csvreader:

            if skip_lines_remaining > 0:
                skip_lines_remaining -= 1
                i += 1
                continue

            address_id = ""
            address = ""
            try:
                address_id = dataline[0]
                address = dataline[1]
            except e:
                # likely hit end-of-file with incomplete CSV entry
                print("broken input, skipping")
                continue

            if address.encode() in bloom_filter:
                found += 1
                print(str(address_id) + "," + address)
                sys.stdout.flush()

            i += 1
            # regular print
            if i % status_print_every == 0:
                print("read " + str(i) + " lines")
                sys.stdout.flush()

    print("found " + str(found) + " address hits in total against the bloom filter")

    # for address in addresses:
    #     if address.encode() in bloom_filter:
    #         print(f'Address {address} is in the filter')
    #     else:
    #         print(f'Address {address} is not in the filter')

def check_address_benchmark_bulk(filter_file, addresses):
    with open(filter_file, 'rb') as f:
        bloom_filter = pickle.load(f)

    for address in addresses:
        if address.encode() in bloom_filter:
            print(f'Address {address} is in the filter')
        else:
            print(f'Address {address} is not in the filter')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Bloom filter operations')
    parser.add_argument('operation', choices=['create', 'check', 'check_csv_bulk', 'benchmark'], help='Operation to perform')
    parser.add_argument('-f', '--filter_file', required=True, help='File to save/load Bloom filter')
    parser.add_argument('-a', '--address', help='Bitcoin address for checking')
    parser.add_argument('-af', '--addresses_file', help='File containing Bitcoin addresses for creating Bloom filter')
    parser.add_argument('-csv', '--addresses_csv_file', help='File containing index,address CSV pairs to check in bulk')
    parser.add_argument('-s', '--skip-input-lines', help='Skip n lines from input')
    args = parser.parse_args()

    if args.operation == 'create':
        if args.addresses_file is None:
            print('You must provide an address file for creating a Bloom filter.')
        else:
            construct_bloom_filter(args.addresses_file, args.filter_file)

    elif args.operation == 'check':
        # TODO require filter file
        if args.address is None:
            print('You must provide an address for checking.')
        else:
            check_address(args.filter_file, args.address)

    elif args.operation == 'check_csv_bulk':
        # TODO require filter file
        if args.addresses_csv_file is None:
            print('You must provide an address CSV file for checking.')
        else:
            skip_lines = 0
            if args.skip_input_lines is not None:
                skip_lines = int(args.skip_input_lines)
                print("skipping " + str(skip_lines) + " lines")
            check_address_csv(args.filter_file, args.addresses_csv_file, skip_lines)

    elif args.operation == 'benchmark':
        # TODO require filter file
        if args.address is None:
            print('You must provide an address for benchmark.')
        else:
            addresses = []
            # run lookup 1M times
            # this is primitive and re-uses the same lookup, not ideal benchmark
            for i in range(1000000):
               addresses.append(args.address)
            check_address_benchmark_bulk(args.filter_file, addresses)
