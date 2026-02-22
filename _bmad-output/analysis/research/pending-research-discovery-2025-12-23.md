---
stepsCompleted: [0]
inputDocuments: []
workflowType: 'research'
lastStep: 0
research_type: 'TBA'
research_topic: 'TBA'
research_goals: 'TBA'
user_name: 'Moe'
date: '2025-12-23'
web_research_enabled: true
source_verification: true
---

# Research Discovery: Temporal Planetarium

**Status:** Awaiting Topic Definition

## Objective
Collaborative discovery with the user to define the research scope, topic, and type.

## Discussion Points
- **Topic:** Technical Identification of Vulnerable Bitcoin Core addresses and design of a Target Test Vector Database.
- **Goals:** 
    1. Map historical Bitcoin Core (Bitcoin-Qt) PRNG vulnerabilities (e.g., CVE-2008-0166).
    2. **On-Chain Identifiability:** Research whether vulnerable wallets (Randstorm/BitcoinJS) exhibit identifiable patterns on the blockchain (e.g., transaction signatures, fee patterns) versus being "invisible" until a collision is found.
    3. **Pre-Launch Detection:** Investigate methodologies for identifying "highly probable" vulnerable targets without running a full brute-force scan (e.g., filtering addresses by creation date or transaction history).
    4. Define technical methodology for reconstructing weak keys vs. harvesting known addresses from public research.
    5. Design a structured database schema for integrating these targets into the Temporal Planetarium codebase.
- **Scope:** Technical evaluation of PRNG implementation flaws and data harvesting strategies.
- **Research Type:** **Technical Research**.

## Preliminary Findings
- **On-Chain Identifiability:** While Bitcoin addresses are "blind" hashes, the **signatures (ECDSA)** generated when a wallet transacts can reveal RNG weaknesses. If any cryptographic nonces ('k' values) are reused or generated with low entropy, the private key can be recovered via signature analysis without brute-force.
- **Pre-Launch Detection:** Effective pre-filtering methodologies involve clustering addresses by **block height (age)**—specifically targeting the 2011-2015 "Randstorm" window—and identifying **implementation-specific fee patterns** or transaction metadata.
- **Public Datasets:** Over 300,000 vulnerable addresses have already been identified by researchers (e.g., Milk Sad/bx 3.x), which can be used to bootstrap a test vector database.

## Recommendation
I recommend proceeding with **Technical Research** because this task requires analyzing specific cryptographic implementation flaws (OpenSSL seeding, early PRNG logic) and designing a technical data artifact (the test vector database).

**Moe, does this scope and the identified detection methodologies align with your vision?**
[C] Continue - Begin technical research with this scope.
