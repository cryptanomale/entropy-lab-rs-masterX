#!/bin/bash
# Upload GPU BIP39 validation test to server and run it

# Upload test to server
echo "Uploading GPU BIP39 validation test to server..."
sshpass -p 'madmad13221' scp -o StrictHostKeyChecking=no gpu_bip39_validator.rs dev@100.115.168.104:~/entropy-lab-rs/tests/

# Run the test
echo "Running GPU BIP39 validation test..."
sshpass -p 'madmad13221' ssh -o StrictHostKeyChecking=no dev@100.115.168.104 '
    cd ~/entropy-lab-rs && \
    cargo test --test gpu_bip39_validator -- --nocapture 2>&1 | tee gpu_bip39_test_output.txt
'

echo "✓ Test complete. Check gpu_bip39_test_output.txt on server for results."
