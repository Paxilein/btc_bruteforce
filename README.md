# Bitcoin Brute Force POC

This GoLang application demonstrates the mathematical impossibility of brute-forcing Bitcoin private keys. It generates random BIP32 master keys (equivalent to 12-word mnemonics) and compares derived addresses against a known address database.

## 🚀 Performance Optimizations

The application includes two modes:
- **Standard Mode**: Direct address comparison (~4-8M keys/sec)
- **Hash160 Optimization**: Binary hash comparison (~12-25M keys/sec) 🔥

## 📋 Prerequisites

- **Go 1.24+** installed
- **Address Database**: Download from [Loyce.club](http://addresses.loyce.club/) and save as `addresses.txt`

## 🔧 Installation & Setup

### 1. Clone and Setup
```bash
git clone
cd btc_bruteforce
go mod tidy
```

### 2. Download Address Database
- Visit [http://addresses.loyce.club/](http://addresses.loyce.club/)
- Download a Bitcoin address list (e.g., `Bitcoin_addresses_LATEST.txt.gz`)
- Extract and rename to `addresses.txt` in the project root

### 3. Convert Addresses (Hash160 Optimization)
For maximum performance, convert addresses to Hash160 format:

```bash
cd tools
go run address-convert.go
```

**Address Converter Features:**
- Converts Bitcoin addresses to 20-byte Hash160 values
- **Intelligent Filtering**: Automatically excludes non-brute-forceable address types (P2SH, P2WSH)
- Only processes P2PKH (1...), P2WPKH (bc1q...), and P2TR (bc1p...) addresses
- Removes duplicates automatically
- ~88% smaller file size vs original addresses
- Progress reporting every 1M addresses

**Example Output:**
```
🔄 Bitcoin Address to Hash160 Converter
=======================================
Input file: ../addresses.txt
Output file: ../address-hashes.txt

Processing addresses...
Processed 10M addresses (116,668 addresses/sec)
✅ Conversion Complete!
========================
Total addresses read: 60226787
Brute-forceable addresses: 52520463
Successfully converted: 44813957
Skipped (non-brute-forceable): 7706324

📊 Address Type Breakdown:
- P2PKH (1...):           22144839 (42.2%) ✅
- P2WPKH (bc1q... 42ch):  18523124 (35.3%) ✅  
- P2SH (3...):            6785537 (12.9%) ❌
- P2WSH (bc1q... 62ch):   920787 (1.8%) ❌
- P2TR (bc1p...):         4152691 (7.9%) ✅

- Original: 52.5M addresses (~292.6MB text)
- Hash160: 44.8M hashes (854.76MB binary)
- Space savings: 41.2% smaller
```

## 🎯 Running the Brute Forcer

### Hash160 Mode (Recommended - Fastest)
```bash
go run btc_bruteforce.go
```
*Automatically uses Hash160 optimization if `address-hashes.txt` exists*

### Standard Mode (Address Comparison)
Edit `btc_bruteforce.go` and set:
```go
const useHashOptimization = false
```

## 🔍 Address Type Support & Filtering

### ✅ Brute-Forceable Address Types (85.4% of all addresses)

**P2PKH (Pay-to-Public-Key-Hash) - Addresses starting with `1`**
- **How it works**: `address = Base58Check(0x00 + Hash160(publicKey))`
- **Brute-forceable**: ✅ Yes - We can generate publicKey and compute Hash160
- **Coverage**: 42.2% of Bitcoin addresses

**P2WPKH (Pay-to-Witness-Public-Key-Hash) - Addresses starting with `bc1q` (42 chars)**
- **How it works**: `address = Bech32("bc", 0x00, Hash160(publicKey))`
- **Brute-forceable**: ✅ Yes - Same Hash160 as P2PKH, different encoding
- **Coverage**: 35.3% of Bitcoin addresses

**P2TR (Pay-to-Taproot) - Addresses starting with `bc1p`**
- **How it works**: `address = Bech32("bc", 0x01, tweaked_publicKey)`
- **Brute-forceable**: ✅ Yes - We can generate key-path spending addresses
- **Coverage**: 7.9% of Bitcoin addresses
- **Note**: Only key-path spending (most common), not script-path

### ❌ Non-Brute-Forceable Address Types (14.6% of all addresses)

**P2SH (Pay-to-Script-Hash) - Addresses starting with `3`**
- **How it works**: `address = Base58Check(0x05 + Hash160(redeemScript))`
- **Why not brute-forceable**: ❌ Requires knowing the original `redeemScript`
- **Problem**: We can't reverse-engineer arbitrary scripts from just the hash
- **Coverage**: 12.9% of Bitcoin addresses (automatically skipped)

**P2WSH (Pay-to-Witness-Script-Hash) - Addresses starting with `bc1q` (62 chars)**
- **How it works**: `address = Bech32("bc", 0x00, SHA256(witnessScript))`
- **Why not brute-forceable**: ❌ Requires knowing the original `witnessScript`
- **Problem**: Uses SHA256 (not Hash160) and needs the full script
- **Coverage**: 1.8% of Bitcoin addresses (automatically skipped)

### 🧠 Technical Explanation

The fundamental difference is:
- **Brute-forceable**: Address = f(publicKey) - We can generate publicKeys
- **Non-brute-forceable**: Address = f(script) - We can't guess arbitrary scripts

**P2SH/P2WSH Examples:**
```
P2SH MultiSig: OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
P2WSH Lightning: Complex time-locked contracts with multiple conditions
```

These scripts can be:
- Multi-signature wallets (2-of-3, 3-of-5, etc.)
- Lightning Network channels
- Atomic swaps
- Time-locked contracts
- Custom smart contracts

**Why we can't brute-force them:**
1. **Infinite script space**: There are unlimited possible scripts
2. **No reverse function**: Can't go from hash back to original script
3. **Spending requires script**: Even if we guess the hash, we need the full script to spend

**Result**: Our brute forcer focuses on the 85.4% of addresses that are theoretically crackable (though still practically impossible due to the vast keyspace).

## ⚙️ Configuration

### CPU Optimization
The application auto-detects your CPU and optimizes worker count:
```go
const (
    numWorkers = 32     // Adjust for your CPU thread count
    batchSize  = 400000 // Tune for your CPU cache size
)
```

**Recommended Settings:**
- **Ryzen 9 7950X3D**: 32 workers, 400K batch
- **Ryzen 9 7900X3D**: 24 workers, 500K batch  
- **Intel i9-13900K**: 32 workers, 300K batch
- **Other CPUs**: Set `numWorkers = your_thread_count`

## 📊 Performance Benchmarks

### Standard Mode (Address Comparison)
- **4M keys/sec** on Ryzen 9 7950X3D
- **Memory**: ~2-4GB RAM
- **Bottleneck**: Base58 encoding/decoding

### Hash160 Mode (Optimized)
- **12-25M keys/sec** on Ryzen 9 7950X3D  
- **Memory**: ~1-2GB RAM
- **Bottleneck**: secp256k1 operations

## 🔍 How It Works

### Address Generation Process
1. **Random Seed**: Generate 128-bit entropy (equivalent to BIP39 12-word mnemonic)
2. **BIP32 Derivation**: HMAC-SHA512 with "Bitcoin seed" → master private key
3. **secp256k1**: Private key → compressed public key
4. **Multi-Address Generation**: From each public key, generate:
   - **P2PKH**: `Base58Check(0x00 + Hash160(publicKey))` → `1...`
   - **P2WPKH**: `Bech32("bc", 0x00, Hash160(publicKey))` → `bc1q...`
   - **P2TR**: `Bech32("bc", 0x01, tweak(publicKey))` → `bc1p...`
5. **Comparison**: Check all three addresses against target database

### Optimization Techniques
- **Bloom Filter**: Probabilistic fast lookup (0.000000001 false positive rate)
- **Memory Pools**: Reduce garbage collection pressure
- **Hash160 Comparison**: Skip expensive Base58 operations
- **Batch Processing**: Minimize mutex contention
- **CPU Affinity**: Optimal thread distribution

## 🎲 Mathematical Reality

**Current Performance (with filtering & Taproot support):**
- **Hash160 Mode**: ~12-25M keys/second
- **Full Address Mode**: ~4-8M keys/second
- **Address Coverage**: 85.4% of all Bitcoin addresses (P2PKH + P2WPKH + P2TR)

**Even at 25M keys/second:**
- **Per Day**: 2.16 trillion keys
- **Per Year**: 788 trillion keys  
- **To exhaust 50% of keyspace**: ~10^59 years
- **Universe age**: ~10^10 years

**Efficiency Gains:**
- **14.6% fewer addresses** to process (P2SH/P2WSH filtered out)
- **3x address coverage** per key (P2PKH + P2WPKH + P2TR from same private key)
- **Effective search rate**: ~75M address comparisons/second in full mode

**Conclusion**: Even with maximum optimization and filtering, brute forcing Bitcoin private keys remains mathematically impossible with current technology.

## 🐛 Troubleshooting

### Common Issues
1. **Out of Memory**: Reduce `numWorkers` or address database size
2. **Slow Performance**: Enable Hash160 optimization
3. **File Not Found**: Ensure `addresses.txt` or `address-hashes.txt` exists
4. **Build Errors**: Check Go version (requires 1.24+)

### Debug Mode
Enable verbose logging:
```go
log.SetLevel(log.DebugLevel)
```

## 📁 Project Structure
```
btc_bruteforce/
├── btc_bruteforce.go      # Main brute forcer
├── addresses.txt          # Bitcoin addresses (download separately)
├── address-hashes.txt     # Converted Hash160 values (generated by address-conserter)
├── foundkey.txt           # Results (if any matches found)
├── tools/
│   └── address-convert.go # Address to Hash160 converter
├── go.mod
└── README.md
```

## ⚠️ Disclaimer

This is a **proof-of-concept** demonstration of Bitcoin's cryptographic security. It is:
- **Not intended** for actual wallet recovery
- **Educational** purposes only
- **Demonstrates** the impossibility of brute force attacks
- **Not optimized** for production use

## 🤝 Contributing

This was my first Go project! Contributions welcome:
- Performance optimizations
- Code review and best practices
- Additional address format support
- GPU acceleration (OpenCL/CUDA)

## � Donations

If this project helped you understand Bitcoin's cryptographic security or you'd like to support development:

**Bitcoin (BTC)**: `bc1q6kwamqynhwl5knvuwm4qlvvr58q4cqv2l9wr9m`
**Ethereum (ETH)**: `0x679FCacEd3E99dd5dAEc27C5D4b9502Dfbd87AC1`
**Ripple (XRP)**: `rf622E9XpZcGNkUgtLZtW1WbbPrtmWYJTT`

Your support is appreciated! 🙏

## �📄 License

See LICENSE file for details.
