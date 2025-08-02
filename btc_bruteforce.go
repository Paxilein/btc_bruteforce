// btc-bruteforce-poc demonstrates the impracticality of brute-forcing Bitcoin private keys.
// It generates random master keys, derives addresses, and checks them against a known list.
// If a match is found, it serializes the master key as a BIP32 xprv and saves the result.
//
// NOTE: This is a proof-of-concept. It is not intended for real wallet recovery or production use.
// The code is intentionally inefficient to highlight the astronomical difficulty of brute-forcing BTC keys.

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/willf/bloom"
)

const (
	numWorkers          = 32                   // Match Ryzen 9 7950X3D's 32 threads for maximum utilization
	errorRate           = 0.000000001          // Bloom filter false positive rate
	addressesFile       = "addresses.txt"      // File containing known BTC addresses (one per line)
	hashesFile          = "address-hashes.bin" // File containing Hash160 values (20 bytes each)
	batchSize           = 400000               // Optimized for 7950X3D's dual-CCD architecture with 3D V-Cache
	useHashOptimization = false                // Set to true to use Hash160 optimization (P2PKH/P2WPKH only), false for full address support (includes P2TR)
)

var (
	bloomFilter *bloom.BloomFilter  // Probabilistic filter for fast address checks
	addressMap  map[string]struct{} // Exact address set for confirmation
	wg          sync.WaitGroup      // WaitGroup for goroutine synchronization
	mutex       sync.Mutex          // Mutex for shared state (counter, file writes)
	counter     int64               // Total keys generated (using int64 for larger counts)

	// Pre-allocate constant BIP32 values to avoid repeated allocations
	xprvVersion     = []byte{0x04, 0x88, 0xAD, 0xE4}
	masterDepth     = byte(0x00)
	zeroFingerprint = []byte{0x00, 0x00, 0x00, 0x00}
	zeroChildNumber = []byte{0x00, 0x00, 0x00, 0x00}

	// Memory pools to reduce garbage collection pressure
	seedPool = sync.Pool{
		New: func() interface{} {
			seed := make([]byte, 16)
			return &seed
		},
	}

	hmacPool = sync.Pool{
		New: func() interface{} {
			return hmac.New(sha512.New, []byte("Bitcoin seed"))
		},
	}
)

// loadAddresses loads BTC addresses from a file into a Bloom filter and a map.
// The Bloom filter allows fast probabilistic checks; the map confirms exact matches.
func loadAddresses(filePath string) (*bloom.BloomFilter, map[string]struct{}) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	// Count addresses by scanning for newlines (for Bloom filter sizing)
	numAddresses := 0
	buf := make([]byte, 64*1024)
	for {
		n, err := file.Read(buf)
		if err != nil {
			break
		}
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				numAddresses++
			}
		}
	}

	bloomFilter := bloom.NewWithEstimates(uint(numAddresses), errorRate)
	addressMap := make(map[string]struct{})

	_, err = file.Seek(0, 0)
	if err != nil {
		log.Fatalf("Failed to reset file pointer: %v", err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		address := scanner.Text()
		bloomFilter.Add([]byte(address))
		addressMap[address] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	fmt.Printf("Loaded %d addresses into Bloom filter.\n", numAddresses)
	return bloomFilter, addressMap
}

// loadHash160Values loads Hash160 values from binary file for faster comparison
func loadHash160Values(filePath string) (*bloom.BloomFilter, map[string]struct{}) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open hash file: %v", err)
	}
	defer file.Close()

	// Get file size to calculate number of 20-byte Hash160 values
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Failed to get file info: %v", err)
	}

	numHashes := int(fileInfo.Size()) / 20
	fmt.Printf("Hash file size: %d bytes, Hash160 count: %d\n", fileInfo.Size(), numHashes)

	bloomFilter := bloom.NewWithEstimates(uint(numHashes), errorRate)
	hashMap := make(map[string]struct{})

	// Read 20-byte Hash160 values
	hash160 := make([]byte, 20)
	for {
		n, err := file.Read(hash160)
		if err != nil || n != 20 {
			break
		}

		// Add to bloom filter and map
		bloomFilter.Add(hash160)
		hashMap[string(hash160)] = struct{}{}
	}

	fmt.Printf("Loaded %d Hash160 values into optimized Bloom filter.\n", numHashes)
	return bloomFilter, hashMap
}

// publicKeyToAllAddresses generates P2PKH, P2WPKH, and P2TR addresses from a private key.
// Returns legacy (P2PKH), SegWit (P2WPKH), and Taproot (P2TR) addresses for maximum coverage.
func publicKeyToAllAddresses(privKey *btcec.PrivateKey, netParams *chaincfg.Params) (legacyAddress, segwitAddress, taprootAddress string, err error) {
	// Get the compressed public key
	pubKey := privKey.PubKey().SerializeCompressed()

	// Calculate Hash160 once and reuse for P2PKH and P2WPKH
	pubKeyHash := btcutil.Hash160(pubKey)

	// Generate legacy P2PKH address (starts with "1")
	legacyAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, netParams)
	if err != nil {
		return "", "", "", err
	}
	legacyAddress = legacyAddr.EncodeAddress()

	// Generate SegWit P2WPKH address (starts with "bc1q")
	segwitAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, netParams)
	if err != nil {
		return "", "", "", err
	}
	segwitAddress = segwitAddr.EncodeAddress()

	// Generate Taproot P2TR address (starts with "bc1p")
	// For key-path spending, we tweak the public key with an empty script tree
	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(privKey.PubKey())), netParams)
	if err != nil {
		return "", "", "", err
	}
	taprootAddress = taprootAddr.EncodeAddress()

	return legacyAddress, segwitAddress, taprootAddress, nil
}

// serializeMasterKey serializes a BIP32 master key (xprv) according to the spec.
// Fields: version, depth, parent fingerprint, child number, chain code, key data, checksum.
func serializeMasterKey(version []byte, depth byte, parentFingerprint []byte, childNumber []byte, chainCode []byte, key []byte) string {
	// Pre-allocate the slice with known capacity to avoid reallocations
	data := make([]byte, 0, 4+1+4+4+32+33+4) // version + depth + fingerprint + child + chaincode + key + checksum
	data = append(data, version...)
	data = append(data, depth)
	data = append(data, parentFingerprint...)
	data = append(data, childNumber...)
	data = append(data, chainCode...)
	data = append(data, key...)

	checksum := sha256.Sum256(data)
	checksum = sha256.Sum256(checksum[:])
	data = append(data, checksum[:4]...)
	return base58.Encode(data)
}

// generateKeys runs in a goroutine, generating random master keys and checking derived addresses.
// If a generated address matches the known set, it saves the xprv and addresses to a file.
func generateKeys(workerID int, useHash160 bool) {
	defer wg.Done()

	// Use faster math/rand with worker-specific seed for better performance
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

	// Use memory pools to reduce allocations
	seedPtr := seedPool.Get().(*[]byte)
	seed := *seedPtr
	defer seedPool.Put(seedPtr)

	hmac512 := hmacPool.Get().(hash.Hash)
	defer hmacPool.Put(hmac512)

	var localCounter int64 // Use int64 to avoid overflow on long runs

	// Pre-allocate byte slices for address string conversion to avoid repeated allocations
	legacyAddrBytes := make([]byte, 0, 34) // Typical P2PKH address length
	segwitAddrBytes := make([]byte, 0, 42) // Typical P2WPKH address length

	// Buffer for HMAC output to avoid allocations
	derived := make([]byte, 64)

	for {
		// Generate random seed - use faster bulk generation
		rng.Read(seed) // Much faster than byte-by-byte generation

		// Reset and reuse the HMAC instead of creating new one each time
		hmac512.Reset()
		hmac512.Write(seed)
		derived = hmac512.Sum(derived[:0]) // Reuse the buffer

		masterPrivateKey := derived[:32]
		privKey, pubKey := btcec.PrivKeyFromBytes(masterPrivateKey)

		// Cache the compressed public key to avoid calling SerializeCompressed twice
		compressedPubKey := pubKey.SerializeCompressed()

		if useHash160 {
			// Hash160 optimization: skip Base58 encoding for faster comparison
			pubKeyHash := btcutil.Hash160(compressedPubKey)

			// Fast Hash160 comparison (no Base58 encoding needed)
			if bloomFilter.Test(pubKeyHash) {
				if _, exists := addressMap[string(pubKeyHash)]; exists {
					// Generate full addresses only when we have a match for logging
					legacyAddr, _ := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
					segwitAddr, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
					legacyAddress := legacyAddr.EncodeAddress()
					segwitAddress := segwitAddr.EncodeAddress()

					fmt.Printf("Worker %d: HOLY GRAIL FOUND! Hash160 match!\n", workerID)
					saveAddressData(legacyAddress, segwitAddress, derived)
				}
			}
		} else {
			// Standard address comparison (slower but with full address type coverage)
			legacyAddress, segwitAddress, taprootAddress, err := publicKeyToAllAddresses(privKey, &chaincfg.MainNetParams)
			if err != nil {
				log.Printf("Worker %d: Failed to generate addresses: %v", workerID, err)
				continue
			}

			// Convert to bytes once for Bloom filter tests (avoiding repeated string->byte conversions)
			legacyAddrBytes = legacyAddrBytes[:0]
			legacyAddrBytes = append(legacyAddrBytes, legacyAddress...)

			segwitAddrBytes = segwitAddrBytes[:0]
			segwitAddrBytes = append(segwitAddrBytes, segwitAddress...)

			// Pre-allocate byte slice for Taproot address
			taprootAddrBytes := make([]byte, 0, 62) // Typical P2TR address length
			taprootAddrBytes = append(taprootAddrBytes, taprootAddress...)

			// Fast Bloom filter check first, then exact match
			if bloomFilter.Test(legacyAddrBytes) || bloomFilter.Test(segwitAddrBytes) || bloomFilter.Test(taprootAddrBytes) {
				if _, exists := addressMap[legacyAddress]; exists {
					fmt.Printf("Worker %d: HOLY GRAIL FOUND! Legacy P2PKH match: %s\n", workerID, legacyAddress)
					saveAddressData(legacyAddress, segwitAddress, derived)
				} else if _, exists := addressMap[segwitAddress]; exists {
					fmt.Printf("Worker %d: HOLY GRAIL FOUND! SegWit P2WPKH match: %s\n", workerID, segwitAddress)
					saveAddressData(legacyAddress, segwitAddress, derived)
				} else if _, exists := addressMap[taprootAddress]; exists {
					fmt.Printf("Worker %d: HOLY GRAIL FOUND! Taproot P2TR match: %s\n", workerID, taprootAddress)
					saveAddressData(legacyAddress, segwitAddress, derived)
				}
			}
		}

		// Only acquire mutex every batchSize keys instead of every key to reduce contention
		localCounter++
		if localCounter%batchSize == 0 {
			mutex.Lock()
			counter += batchSize
			fmt.Printf("Total keys generated: %d (Worker %d just contributed %dk)\n", counter, workerID, batchSize/1000)
			mutex.Unlock()
		}
	}
}

// saveAddressData serializes the master key as xprv and saves matching addresses to a file.
// Uses BIP32 fields for serialization with pre-allocated constants.
func saveAddressData(legacyAddress, segwitAddress string, derived []byte) {
	chainCode := derived[32:]
	// Pre-allocate keyData slice to avoid allocation in append
	keyData := make([]byte, 33)
	keyData[0] = 0x00
	copy(keyData[1:], derived[:32])

	xprv := serializeMasterKey(xprvVersion, masterDepth, zeroFingerprint, zeroChildNumber, chainCode, keyData)

	// Log the miraculous discovery
	fmt.Printf("==============================================\n")
	fmt.Printf("🎉 IMPOSSIBLE HAPPENED! MATCHING ADDRESS FOUND! 🎉\n")
	fmt.Printf("Legacy Address: %s\n", legacyAddress)
	fmt.Printf("SegWit Address: %s\n", segwitAddress)
	fmt.Printf("xprv: %s\n", xprv)
	fmt.Printf("==============================================\n")

	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile("foundkey.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open result file: %v", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("=== MIRACLE OCCURRENCE ===\nLegacy Address: %s\nSegWit Address: %s\nxprv: %s\n\n", legacyAddress, segwitAddress, xprv))
	if err != nil {
		log.Printf("Failed to write result: %v", err)
	}
}

// main initializes the Bloom filter and address map, then starts key generation workers.
// Waits for all workers to finish (which, in this infinite loop, never happens).
func main() {
	var inputFile string
	var useHash160 bool

	// Handle command line arguments with intelligent defaults
	if len(os.Args) == 1 {
		// No arguments - check if binary hash file exists
		if _, err := os.Stat(hashesFile); err == nil {
			// Binary hash file exists - use hash160 optimization
			inputFile = hashesFile
			useHash160 = true
			fmt.Printf("Auto-detected %s - using Hash160 optimization mode\n", hashesFile)
		} else {
			// Fall back to text file
			inputFile = addressesFile
			useHash160 = false
			fmt.Printf("Using default: %s (full address mode)\n", addressesFile)
		}
	} else if len(os.Args) == 2 {
		// One argument - input file specified
		inputFile = os.Args[1]
		useHash160 = false
	} else if len(os.Args) == 3 && os.Args[2] == "-hash160" {
		// Two arguments - input file and hash160 flag
		inputFile = os.Args[1]
		useHash160 = true
	} else {
		// Invalid arguments - show usage
		fmt.Println("Usage: btc_bruteforce [addresses.txt] [options]")
		fmt.Println("  addresses.txt  - File containing Bitcoin addresses (one per line)")
		fmt.Println("                   Default: Auto-detects address-hashes.bin or addresses.txt")
		fmt.Println("  -hash160       - Use Hash160 optimization (P2PKH/P2WPKH only)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  btc_bruteforce                    # Auto-detects best file and mode")
		fmt.Println("  btc_bruteforce addresses.txt      # Full address mode")
		fmt.Println("  btc_bruteforce test-taproot.txt   # Full address mode with custom file")
		fmt.Println("  btc_bruteforce addresses.txt -hash160  # Hash160 optimization mode")
		os.Exit(1)
	} // Use all available threads for Ryzen 9 7900X3D (24 threads)
	optimalWorkers := numWorkers
	if runtime.NumCPU() < numWorkers {
		optimalWorkers = runtime.NumCPU()
	}

	fmt.Println("🚀 Bitcoin Private Key Brute Force POC")
	fmt.Println("====================================================================")
	fmt.Printf("CPU: %d cores/%d threads\n", runtime.NumCPU()/2, runtime.NumCPU())
	fmt.Printf("Workers: %d (utilizing all threads)\n", optimalWorkers)
	if useHash160 {
		fmt.Printf("Target file: %s (Hash160 optimization enabled! 🚀)\n", hashesFile)
		fmt.Println("Note: Hash160 mode only supports P2PKH (1...) and P2WPKH (bc1q 42ch) addresses")
	} else {
		fmt.Printf("Target file: %s (full address comparison with Taproot support)\n", inputFile)
		fmt.Println("Note: Full mode supports P2PKH (1...), P2WPKH (bc1q 42ch), and P2TR (bc1p...) addresses")
	}
	fmt.Println("WARNING: This demonstrates the mathematical impossibility of brute-forcing Bitcoin.")
	fmt.Printf("Even at 10M keys/second, you'd need ~10^59 years to have a decent chance.\n")
	fmt.Printf("The universe is only ~10^10 years old. You do the math.\n\n")

	if useHash160 {
		bloomFilter, addressMap = loadHash160Values(hashesFile)
	} else {
		bloomFilter, addressMap = loadAddresses(inputFile)
	}

	// Set GOMAXPROCS to match worker count for optimal scheduling
	runtime.GOMAXPROCS(optimalWorkers)

	fmt.Printf("Starting %d optimized workers (GOMAXPROCS=%d)...\n", optimalWorkers, optimalWorkers)
	fmt.Println("Press Ctrl+C to stop this exercise in futility.")

	for i := 0; i < optimalWorkers; i++ {
		wg.Add(1)
		go generateKeys(i, useHash160)
	}

	wg.Wait()
}
