# DeviceVCRecord Contract Deployment Guide

## Prerequisites

- [Foundry](https://book.getfoundry.sh/) toolchain: `forge`, `cast`
- RPC endpoint for an EVM-compatible chain
- Private key with gas tokens for deployment

## Deploy

```bash
# Set environment variables
export RPC_URL=<chain RPC URL>
export PRIVATE_KEY=<deployer private key>

# Deploy contract
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  contracts/DeviceVCRecord.sol:DeviceVCRecord
```

After deployment, the contract address is printed (`Deployed to: 0x...`). Use this address
as `CHAIN_CONTRACT_ADDRESS` in the verifier configuration.

## Interaction Examples

```bash
# Query the latest VC for a device (pubkey_hash must be bytes32 hex)
cast call <CONTRACT_ADDRESS> \
  "getVC(bytes32)(string,uint256)" \
  <DEVICE_PUBKEY_HASH>

# Query the VC record count for a device
cast call <CONTRACT_ADDRESS> \
  "vcCount(bytes32)" \
  <DEVICE_PUBKEY_HASH>

# View VCStored events
cast logs --address <CONTRACT_ADDRESS> \
  "VCStored(bytes32,uint256)"
```
