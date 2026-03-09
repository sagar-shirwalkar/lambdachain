# LambdaChain

![Haskell](https://img.shields.io/badge/Haskell-5e5086?style=for-the-badge&logo=haskell&logoColor=white)
![GHC](https://img.shields.io/badge/GHC-9.6.7-fbbb2b?style=for-the-badge)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagar-shirwalkar/lambdachain/ci.yml?branch=main&style=for-the-badge)
![GitHub Tag](https://img.shields.io/github/v/tag/sagar-shirwalkar/lambdachain?style=for-the-badge&color=blue)
![GitHub License](https://img.shields.io/github/license/sagar-shirwalkar/lambdachain?style=for-the-badge&color=purple)

A Haskell-based blockchain implementation with a secure UTXO-style ledger, Zero-Knowledge Proofs (ZKP), Transaction Verification, and account-based transactions.

## Features

- **Account-based Blockchain**: UTXO-style ledger with account states, balances, and nonces
- **Schnorr-based ZKP**: Zero-knowledge proofs for transaction authorization
- **Proof-of-Work (PoW)**: Mining with configurable difficulty and block rewards
- **Block Rewards**: Coinbase transactions reward miners (halving every 210,000 blocks like Bitcoin)
- **Merkle Trees**: Transaction verification via Merkle root hashing
- **Cryptographic Security**:
  - SHA-256 and Blake2b hashing for block integrity
  - AES-256-GCM for encrypted transaction data
  - Environment-based key management
- **Chain Validation**: Full chain integrity verification with difficulty adjustment
- **REST API**: HTTP server for blockchain operations

## Prerequisites

- **Glasgow Haskell Compiler (GHC)**: v9.6.7
- **Cabal**: v3.14.2.0
- **Stack**: v3.7.1

```bash
# macOS
brew install ghc stack

# Ubuntu/Debian
sudo apt-get install ghc stack
```

## Installation

```bash
# Build the project
stack build

# Run tests
stack test
```

## Running the Application

```bash
stack run
```

The server runs on `http://localhost:3000`.

## API Endpoints

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Welcome message |
| GET | `/blockchain` | Get blockchain state |
| GET | `/ledger` | Get ledger state |
| GET | `/balance/{address}` | Get account balance |
| GET | `/pending` | Get pending transactions |
| GET | `/validate` | Validate blockchain |

### Production Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register` | Register account with public key |
| POST | `/transaction` | Submit pre-signed transaction |
| POST | `/mine` | Mine pending transactions |

### Debug Endpoints (testing only)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/debug/register` | Register with secret key |
| POST | `/debug/transaction` | Create and submit transaction |

## Example Usage

```bash
# Register alice (debug mode)
curl -X POST http://localhost:3000/debug/register \
  -H "Content-Type: application/json" \
  -d '{"secretKey": 11111, "initialBalance": 1000}'

# Register bob (debug mode)
curl -X POST http://localhost:3000/debug/register \
  -H "Content-Type: application/json" \
  -d '{"secretKey": 22222, "initialBalance": 500}'

# Get balance
curl http://localhost:3000/balance/<alice-address>

# Validate blockchain
curl http://localhost:3000/validate

# Mine block
curl -X POST http://localhost:3000/mine
```

## Architecture

### Module Structure

- **Block.Block**: Block data structure, hash computation, genesis block creation
- **Blockchain.Blockchain**: Chain management, transaction submission, mining with PoW
- **Transaction.Transaction**: Transaction creation, verification, ledger operations
- **Consensus.Consensus**: PoW mining, difficulty adjustment, block validation, chain selection
- **ZKP.ZKP**: Schnorr-based zero-knowledge proof system
- **Cryptography.Hash**: SHA-256 and Blake2b hashing utilities
- **Cryptography.HomomorphicEncryption**: AES-256-GCM encryption
- **MerkleTree.MerkleTree**: Merkle tree implementation for transaction verification
- **Security.KeyEnv**: Environment-based key management

### Transaction Flow

1. Account registers with public key and initial balance
2. Transaction created with sender, recipient, amount, nonce
3. ZKP generated proving sender owns the secret key
4. Transaction submitted to pending pool
5. Miner collects pending transactions and creates coinbase reward
6. PoW mining finds valid nonce meeting difficulty target
7. Block added to chain, ledger updated, miner receives block reward

### Mining & Block Rewards

- **Difficulty**: Default 2 leading zeros, adjustable (max 8)
- **Target Time**: 2 minutes between blocks (for testing)
- **Block Reward**: Starts at 50 coins, halves every 210,000 blocks
- **Coinbase**: Special transaction with miner address as recipient

## Testing

```bash
stack test
```

97 test cases covering ZKP, transactions, block validation, consensus (PoW), Merkle trees, encryption, blockchain operations, and integration scenarios.


## License

Released under [MIT](/LICENSE) by [@sagar-shirwalkar](https://github.com/sagar-shirwalkar).
