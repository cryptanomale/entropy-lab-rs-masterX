#!/bin/bash
# Automated Testnet Funding Script for Randstorm Test Vector
# Requires: Bitcoin Core with testnet enabled

set -e  # Exit on error

# Configuration
TARGET_ADDRESS="n2ViH2xX7QgbouDvK2tdLmnyK2rQPYqoA1"
AMOUNT="0.001"  # tBTC
LABEL="randstorm_test_key_500"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Testnet Funding Script - Randstorm Validation${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if bitcoin-cli is available
if ! command -v bitcoin-cli &> /dev/null; then
    echo -e "${RED}❌ Error: bitcoin-cli not found${NC}"
    echo ""
    echo "Please install Bitcoin Core:"
    echo "  macOS: brew install bitcoin"
    echo "  Linux: sudo apt-get install bitcoind"
    echo ""
    echo "Or use manual funding method:"
    echo "  https://testnet-faucet.mempool.co/"
    echo "  Address: ${TARGET_ADDRESS}"
    exit 1
fi

# Check if testnet node is running
echo -e "${YELLOW}🔍 Checking Bitcoin Core testnet connection...${NC}"
if ! bitcoin-cli -testnet getblockchaininfo &> /dev/null; then
    echo -e "${RED}❌ Error: Bitcoin Core testnet not running${NC}"
    echo ""
    echo "Start Bitcoin Core in testnet mode:"
    echo "  bitcoind -testnet -daemon"
    echo ""
    echo "Or add to bitcoin.conf:"
    echo "  testnet=1"
    echo "  daemon=1"
    echo ""
    echo "Alternatively, use manual funding:"
    echo "  https://testnet-faucet.mempool.co/"
    exit 1
fi

echo -e "${GREEN}✓ Bitcoin Core testnet connected${NC}"
echo ""

# Check wallet balance
echo -e "${YELLOW}💰 Checking wallet balance...${NC}"
BALANCE=$(bitcoin-cli -testnet getbalance)
REQUIRED=$(echo "$AMOUNT + 0.0001" | bc)  # Amount + fee

if (( $(echo "$BALANCE < $REQUIRED" | bc -l) )); then
    echo -e "${RED}❌ Insufficient testnet balance: ${BALANCE} tBTC${NC}"
    echo -e "${YELLOW}   Required: ${REQUIRED} tBTC (${AMOUNT} + 0.0001 fee)${NC}"
    echo ""
    echo "Get testnet coins from faucets:"
    echo "  • https://testnet-faucet.mempool.co/"
    echo "  • https://coinfaucet.eu/en/btc-testnet/"
    echo "  • https://bitcoinfaucet.uo1.net/"
    echo ""
    echo "Then import to Bitcoin Core:"
    echo "  bitcoin-cli -testnet getnewaddress"
    echo "  # Send tBTC from faucet to that address"
    exit 1
fi

echo -e "${GREEN}✓ Sufficient balance: ${BALANCE} tBTC${NC}"
echo ""

# Send transaction
echo -e "${YELLOW}📤 Sending ${AMOUNT} tBTC to ${TARGET_ADDRESS}...${NC}"
TXID=$(bitcoin-cli -testnet sendtoaddress "$TARGET_ADDRESS" "$AMOUNT" "" "" false)

if [ -z "$TXID" ]; then
    echo -e "${RED}❌ Transaction failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Transaction broadcast successfully!${NC}"
echo ""
echo -e "${BLUE}Transaction Details:${NC}"
echo "  TXID: ${TXID}"
echo "  Amount: ${AMOUNT} tBTC"
echo "  To: ${TARGET_ADDRESS}"
echo ""

# Monitor confirmation
echo -e "${YELLOW}⏳ Waiting for confirmation...${NC}"
echo "   (This typically takes 10-30 minutes on testnet)"
echo ""

CONFIRMATIONS=0
CHECKS=0
MAX_CHECKS=60  # 30 minutes (30 sec intervals)

while [ $CONFIRMATIONS -lt 1 ] && [ $CHECKS -lt $MAX_CHECKS ]; do
    sleep 30
    CHECKS=$((CHECKS + 1))
    
    # Get transaction details
    TX_INFO=$(bitcoin-cli -testnet gettransaction "$TXID" 2>/dev/null || echo "")
    
    if [ -n "$TX_INFO" ]; then
        CONFIRMATIONS=$(echo "$TX_INFO" | grep -o '"confirmations": [0-9]*' | awk '{print $2}')
        
        if [ -z "$CONFIRMATIONS" ]; then
            CONFIRMATIONS=0
        fi
        
        echo -ne "\r   Confirmations: ${CONFIRMATIONS}/1 (checked ${CHECKS} times)"
    fi
done

echo ""
echo ""

if [ $CONFIRMATIONS -ge 1 ]; then
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ FUNDING COMPLETE - Transaction Confirmed!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}Verification:${NC}"
    echo "  Address: ${TARGET_ADDRESS}"
    echo "  Balance: ${AMOUNT} tBTC"
    echo "  TXID: ${TXID}"
    echo "  Confirmations: ${CONFIRMATIONS}"
    echo ""
    echo -e "${BLUE}Block Explorer:${NC}"
    echo "  https://blockstream.info/testnet/address/${TARGET_ADDRESS}"
    echo "  https://blockstream.info/testnet/tx/${TXID}"
    echo ""
    echo -e "${GREEN}✓ Ready to proceed to Phase 3 (Scanner Configuration)${NC}"
    echo ""
    
    # Save transaction details
    cat > /tmp/randstorm_funding_tx.json <<EOF
{
  "address": "${TARGET_ADDRESS}",
  "amount": "${AMOUNT}",
  "txid": "${TXID}",
  "confirmations": ${CONFIRMATIONS},
  "funded_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "confirmed"
}
EOF
    echo -e "${BLUE}Transaction details saved to: /tmp/randstorm_funding_tx.json${NC}"
    
else
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  ⏰ Timeout - Transaction Still Pending${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Transaction broadcast but not yet confirmed."
    echo "Continue monitoring manually:"
    echo ""
    echo "  bitcoin-cli -testnet gettransaction ${TXID}"
    echo ""
    echo "Or check block explorer:"
    echo "  https://blockstream.info/testnet/tx/${TXID}"
    echo ""
    echo "The transaction should confirm within 1-2 hours."
    echo "Proceed to Phase 3 once confirmed."
    echo ""
fi
