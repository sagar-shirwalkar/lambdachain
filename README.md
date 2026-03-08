# LambdaChain

![Haskell](https://img.shields.io/badge/Haskell-5e5086?style=flat-square&logo=haskell&logoColor=white)
![GHC](https://img.shields.io/badge/GHC-9.6.7-fbbb2b?style=flat-square)
![GitHub branch status](https://img.shields.io/github/checks-status/sagar-shirwalkar/lambdachain/main?style=flat-square)
![GitHub Tag](https://img.shields.io/github/v/tag/sagar-shirwalkar/lambdachain?style=flat-square&color=green)
![GitHub License](https://img.shields.io/github/license/sagar-shirwalkar/lambdachain?style=flat-square&color=purple)

A Haskell-based blockchain implementation with advanced security features including Zero-Knowledge Proofs (ZKP), homomorphic encryption, Merkle trees, and Proof-of-Work consensus mechanism.

## Features

- **Blockchain Core**: Complete blockchain implementation with block structure, chain validation, and chain management
- **Proof-of-Work Consensus**: Secure consensus mechanism with difficulty adjustment
- **Merkle Trees**: Efficient transaction verification using Merkle tree data structure
- **Cryptographic Security**: 
  - BLAKE2b hashing algorithm
  - Zero-Knowledge Proofs for private transactions
  - Homomorphic encryption for sensitive data
- **Network Layer**: P2P communication for blockchain data exchange
- **REST API**: Web server interface for blockchain operations
- **Security Features**: Private transactions, encryption/decryption, ZKP verification

## Prerequisites

### Required Software

1. **Haskell GHC**: The Glasgow Haskell Compiler

   ```bash
   # macOS (Homebrew)
   brew install ghc

   # Ubuntu/Debian
   sudo apt-get install ghc

   # Download from: https://www.haskell.org/ghc/
   ```

2. **Cabal**: Haskell build system

   ```bash
   # macOS (Homebrew)
   brew install cabal-install

   # Ubuntu/Debian
   sudo apt-get install cabal-install

   # Download from: https://www.haskell.org/cabal/
   ```

3. **Stack** (Alternative build tool - recommended)

   ```bash
   curl -sSL https://get.haskellstack.org/ | sh
   ```

### System Dependencies

- **BLAKE2 library**: Cryptographic hashing
- **Wai/Warp**: HTTP server framework
- **Aeson**: JSON serialization
- **Network**: Socket networking

## Installation

### Using Cabal

```bash
# Update package list
cabal update

# Build the project
cabal build

# Install dependencies (automatically handled by build)
cabal install --dependencies-only
```

### Using Stack (Recommended)

```bash
# Build the project
stack build

# Run tests (if available)
stack test
```

## Running the Application

### Development Mode

```bash
# Using runghc for quick testing
runghc src/app/Main.hs

# Using cabal
cabal run lambdachain-exe

# Using stack
stack run
```

### Production Mode

```bash
# Build optimized executable
cabal build --enable-optimizations

# Run the executable
./dist/build/lambdachain-exe/lambdachain-exe
```

## API Endpoints

The application runs on `http://localhost:3000` and provides the following endpoints:

- `GET /` - Welcome message
- `GET /blockchain` - Get current blockchain state
- `GET /block` - Add a new block with sample transactions
- `GET /validate` - Validate the blockchain integrity

### Example Usage

```bash
# Get current blockchain
curl http://localhost:3000/blockchain

# Add a new block
curl http://localhost:3000/block

# Validate blockchain
curl http://localhost:3000/validate
```

## Code Examples

### Creating a Blockchain

```haskell
import Blockchain.Blockchain

-- Create new blockchain with difficulty level 4
let blockchain = newBlockchain 4
```

### Adding Blocks

```haskell
-- Add transactions to the blockchain
let updatedBlockchain = addBlock blockchain ["Transaction 1", "Transaction 2"]
```

### Creating Private Transactions

```haskell
import Security.Security

-- Create a private transaction with ZKP
let zkp = createPrivateTransaction "Secret transaction data"

-- Verify the transaction
let isValid = verifyPrivateTransaction zkp
```

### Homomorphic Encryption

```haskell
import Security.HomomorphicEncryption

-- Encrypt sensitive data
let encrypted = encryptData "sensitive data" "encryption key"

-- Decrypt the data
let decrypted = decryptData "encryption key" encrypted
```

## Security Considerations

### Current Implementation

- XOR-based encryption (for demonstration purposes only)
- Basic ZKP structure (verification logic needs production implementation)
- Proof-of-Work consensus (secure difficulty adjustment needed)

### Production Recommendations

1. **Replace XOR encryption** with industry-standard algorithms (AES, RSA)
2. **Implement proper ZKP verification** with cryptographic libraries
3. **Add transaction signing** (digital signatures)
4. **Implement persistent storage** (database backend)
5. **Add rate limiting** and input validation for network requests
6. **Use proper random number generation** for cryptographic operations
7. **Add Sybil attack protection** in the consensus mechanism

## Performance Optimizations

The implementation includes several performance considerations:

- Efficient Merkle tree construction
- Optimized hash calculation
- Memory-efficient blockchain storage
- Batch processing for network operations

## Development

### Project Structure

- **Modular architecture**: Each component is in its own module
- **Type safety**: Strong Haskell type system prevents many runtime errors
- **Pure functions**: Most functions are pure, making testing easier
- **Immutable data**: Data structures are immutable by default

### Adding New Features

1. Create new modules in the `src/` directory
2. Follow the naming convention: `Module.ModuleName`
3. Update `lambdachain.cabal` with new modules
4. Ensure proper module exports and imports

### Testing

```bash
# Run tests (if implemented)
stack test

# Build with profiling
cabal build --enable-profiling
```

## Troubleshooting

### Common Issues

1. **BLAKE2 not found**
   ```bash
   cabal install blake2
   ```

2. **Port 3000 already in use**
   - Change the port in `src/app/Main.hs` (line 15)
   - Or stop the process using port 3000

3. **Module not found errors**
   - Ensure `lambdachain.cabal` lists all modules
   - Clean build directory: `cabal clean`

## Dependencies

See `lambdachain.cabal` for the complete list of dependencies:

- `base >=4.7 && <5`
- `blake2` - Cryptographic hashing
- `bytestring` - Efficient byte array handling
- `aeson` - JSON serialization
- `network` - Network communication
- `wai` - Web application interface
- `warp` - HTTP server
- `http-types` - HTTP type definitions

## License

Released under [MIT](/LICENSE) by [@sagar-shirwalkar](https://github.com/sagar-shirwalkar).

## Contributing

Contributions are welcome! Please ensure:

- Code follows Haskell best practices
- All functions are properly typed
- Tests are included for new features
- Documentation is updated

## Acknowledgments

This project demonstrates key blockchain concepts implemented in functional Haskell, showcasing the benefits of strong typing and functional programming for secure, reliable systems.
