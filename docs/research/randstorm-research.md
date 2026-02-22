# Randstorm (Keybleed) Vulnerability Brief

## What is Randstorm
- A weakness in BitcoinJS-lib ≤0.1.3 (2011–2015) due to JSBN `SecureRandom()` falling back to `Math.random()` when `navigator.appVersion < "5"` check fails.
- Browsers of that era seeded `Math.random()` with low entropy (often time) and used non-cryptographic PRNGs (e.g., V8 MWC1616), leading to predictable ARC4-seeded private keys.
- First public note: “Ketamine” on bitcoin-dev (Apr 2018). Weaponized analysis: Unciphered “Randstorm” / Keybleed (Nov 2023).

## Root Cause (canonical vulnerable path)
1. Pool of 256 bytes filled via `Math.floor(65536 * Math.random())` split into two bytes (high then low) — no crypto source.
2. `seedTime()` XORs low 32 bits of the timestamp into the first 4 bytes.
3. ARC4 initialized with that pool; first 32 ARC4 bytes used as private key (or feed JSBN BigInteger RNG).
4. Resulting key space collapses from 256 bits to tens of bits; brute-forceable over timestamp/PRNG state.

## Affected footprint
- Wallets generated in-browser with BitcoinJS-lib 0.1.x/JSBN between ~2011–2015.
- Known impacted ecosystems: Blockchain.info legacy web wallet, Coinpunk, BitAddress pre-2013, Dogechain/QuickCoin and other BitcoinJS-derived web wallets.
- Public example (for testing only): `1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD` (first tx ~2014-03-16 23:48:51 GMT-7 → 1395038931000 ms). Reproducing its key requires the precise Math.random state, not just the timestamp.

## Browser PRNG notes (2011–2014)
- Chrome/V8: MWC1616 (`s1=18000*(s1&0xFFFF)+(s1>>16)`, `s2=30903*(s2&0xFFFF)+(s2>>16)`, output `(s1<<16)+s2`, normalized to 2³²).
- Firefox/SpiderMonkey (same era): similar MWC-based Math.random().
- Safari/WebKit JSC: separate weak PRNG, also time-seeded, non-CSPRNG.
- Real browsers mixed OS entropy; timestamp-only PoCs may not match real-world seeds without more state.

## Risk
- Keys may have <2⁴⁸ effective entropy; attackers can brute force timestamp/PRNG state and recover private keys.
- Media estimates suggested up to ~1.4M BTC potentially at risk (upper-bound; not confirmed spendable).

## Detection / validation
- Use Unciphered’s checker: https://keybleed.com (no public API).
- Internal validation: reproduce JSBN rng.js + prng4.js flow with browser-accurate Math.random and search over plausible timestamp windows; confirm derived addresses against target lists.
- Beware: Some community PoCs (e.g., RandstormBTC Python scripts) simplify the RNG (e.g., Python MT, 32-byte pools) and do not match real BitcoinJS behavior.

## Mitigation
- Move funds from any wallet generated in-browser with BitcoinJS ≤0.1.3 (2011–2015) to a new wallet using a modern CSPRNG (hardware wallet preferred).
- For incident response: identify creation timeframe; widen timestamp windows; confirm via keybleed.com; never expose private keys.

## Implementation checklist (for engineers)
- Replicate JSBN rng.js + prng4.js exactly: pool fill order, timestamp XOR, ARC4 init, first 32 bytes → privkey.
- Implement browser PRNGs for target period (V8 MWC1616, SpiderMonkey analogue, JSC) with correct seeding assumptions.
- Support compressed/uncompressed pubkeys when deriving addresses for matching.
- Provide sweep modes over timestamp windows; include configurable Math.random seed overrides for testing.
- Validate against known test vectors and any internal confirmed vulnerable addresses.

## Key references
- Unciphered/Keybleed disclosure (Nov 2023): https://keybleed.com
- TechTarget coverage: “Cryptocurrency wallets might be vulnerable to Randstorm flaw” (Nov 2023)
- Cointelegraph summary (Nov 2023)
- BitcoinJS 0.1.3 (cdnjs mirror): https://cdnjs.cloudflare.com/ajax/libs/bitcoinjs-lib/0.1.3/bitcoinjs-min.js
- JSBN rng/prng sources: `rng.js`, `prng4.js` (bundled in BitcoinJS 0.1.3)
- RandstormBTC community repo: https://github.com/RandstormBTC/randstorm (note: contains simplified PoCs, not authoritative RNG) 

