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
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/willf/bloom"
)

const (
	numWorkers    = 16              // Number of concurrent goroutines for key generation
	errorRate     = 0.000000001     // Bloom filter false positive rate
	addressesFile = "addresses.txt" // File containing known BTC addresses (one per line)
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

// publicKeyToAddress generates a Bitcoin address from a compressed public key.
// Supports both legacy (P2PKH) and SegWit (P2WPKH) formats.
func publicKeyToAddress(pubKey []byte, netParams *chaincfg.Params, isSegWit bool) (string, error) {
	pubKeyHash := btcutil.Hash160(pubKey)

	if isSegWit {
		address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, netParams)
		if err != nil {
			return "", err
		}
		return address.EncodeAddress(), nil
	}

	address, err := btcutil.NewAddressPubKeyHash(pubKeyHash, netParams)
	if err != nil {
		return "", err
	}
	return address.EncodeAddress(), nil
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
func generateKeys(workerID int) {
	defer wg.Done()

	// Pre-allocate reusable buffers outside the loop to minimize allocations
	seed := make([]byte, 16)
	hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
	var localCounter int64 // Use int64 to avoid overflow on long runs

	// Pre-allocate byte slices for address string conversion to avoid repeated allocations
	legacyAddrBytes := make([]byte, 0, 34) // Typical P2PKH address length
	segwitAddrBytes := make([]byte, 0, 42) // Typical P2WPKH address length

	for {
		// Generate random seed - reuse existing slice
		_, err := rand.Read(seed)
		if err != nil {
			log.Printf("Worker %d: Failed to generate seed: %v", workerID, err)
			continue
		}

		// Reset and reuse the HMAC instead of creating new one each time
		hmac512.Reset()
		hmac512.Write(seed)
		derived := hmac512.Sum(nil)

		masterPrivateKey := derived[:32]
		_, pubKey := btcec.PrivKeyFromBytes(masterPrivateKey)

		// Cache the compressed public key to avoid calling SerializeCompressed twice
		compressedPubKey := pubKey.SerializeCompressed()

		// Generate legacy and SegWit addresses
		legacyAddress, err := publicKeyToAddress(compressedPubKey, &chaincfg.MainNetParams, false)
		if err != nil {
			log.Printf("Worker %d: Failed to generate legacy address: %v", workerID, err)
			continue
		}

		segwitAddress, err := publicKeyToAddress(compressedPubKey, &chaincfg.MainNetParams, true)
		if err != nil {
			log.Printf("Worker %d: Failed to generate SegWit address: %v", workerID, err)
			continue
		}

		// Convert to bytes once for Bloom filter tests (avoiding repeated string->byte conversions)
		legacyAddrBytes = legacyAddrBytes[:0]
		legacyAddrBytes = append(legacyAddrBytes, legacyAddress...)

		segwitAddrBytes = segwitAddrBytes[:0]
		segwitAddrBytes = append(segwitAddrBytes, segwitAddress...)

		// Fast Bloom filter check first, then exact match
		if bloomFilter.Test(legacyAddrBytes) || bloomFilter.Test(segwitAddrBytes) {
			if _, exists := addressMap[legacyAddress]; exists {
				fmt.Printf("Worker %d: HOLY GRAIL FOUND! Legacy match: %s\n", workerID, legacyAddress)
				saveAddressData(legacyAddress, segwitAddress, derived)
			} else if _, exists := addressMap[segwitAddress]; exists {
				fmt.Printf("Worker %d: HOLY GRAIL FOUND! SegWit match: %s\n", workerID, segwitAddress)
				saveAddressData(legacyAddress, segwitAddress, derived)
			}
		}

		// Only acquire mutex every 10M keys instead of every key to reduce contention
		localCounter++
		if localCounter%10000000 == 0 {
			mutex.Lock()
			counter += 10000000
			fmt.Printf("Total keys generated: %d (Worker %d just contributed 10M)\n", counter, workerID)
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
	fmt.Println("🚀 Bitcoin Private Key Brute Force POC")
	fmt.Println("=======================================")
	fmt.Printf("Workers: %d\n", numWorkers)
	fmt.Printf("Target addresses file: %s\n", addressesFile)
	fmt.Println("WARNING: This demonstrates the mathematical impossibility of brute-forcing Bitcoin.")
	fmt.Printf("Even at 10M keys/second, you'd need ~10^59 years to have a decent chance.\n")
	fmt.Printf("The universe is only ~10^10 years old. You do the math.\n\n")

	bloomFilter, addressMap = loadAddresses(addressesFile)

	fmt.Printf("Starting %d optimized workers...\n", numWorkers)
	fmt.Println("Press Ctrl+C to stop this exercise in futility.")

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go generateKeys(i)
	}

	wg.Wait()
}
