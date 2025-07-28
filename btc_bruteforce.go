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
    numWorkers    = 16                // Number of concurrent goroutines for key generation
    errorRate     = 0.000000001       // Bloom filter false positive rate
    addressesFile = "addresses.txt"   // File containing known BTC addresses (one per line)
)

var (
    bloomFilter *bloom.BloomFilter    // Probabilistic filter for fast address checks
    addressMap  map[string]struct{}   // Exact address set for confirmation
    wg          sync.WaitGroup        // WaitGroup for goroutine synchronization
    mutex       sync.Mutex            // Mutex for shared state (counter, file writes)
    counter     int                   // Total keys generated (for progress reporting)
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
    if isSegWit {
        pubKeyHash := btcutil.Hash160(pubKey)
        address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, netParams)
        if err != nil {
            return "", err
        }
        return address.EncodeAddress(), nil
    }

    pubKeyHash := btcutil.Hash160(pubKey)
    address, err := btcutil.NewAddressPubKeyHash(pubKeyHash, netParams)
    if err != nil {
        return "", err
    }

    return address.EncodeAddress(), nil
}

// serializeMasterKey serializes a BIP32 master key (xprv) according to the spec.
// Fields: version, depth, parent fingerprint, child number, chain code, key data, checksum.
// ...existing code...
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
// ...existing code...
// generateKeys runs in a goroutine, generating random master keys and checking derived addresses.
// If a generated address matches the known set, it saves the xprv and addresses to a file.
func generateKeys(workerID int) {
    defer wg.Done()

    for {
        // Generate a random seed (16 bytes for POC; not BIP32 standard)
        seed := make([]byte, 16)
        _, err := rand.Read(seed)
        if err != nil {
            log.Fatal("Failed to generate seed:", err)
        }

        // Derive master key using HMAC-SHA512 ("Bitcoin seed" as key)
        hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
        hmac512.Write(seed)
        derived := hmac512.Sum(nil)

        masterPrivateKey := derived[:32]
        privKey, _ := btcec.PrivKeyFromBytes(masterPrivateKey)
        pubKey := privKey.PubKey()

        // Generate legacy and SegWit addresses
        legacyAddress, err := publicKeyToAddress(pubKey.SerializeCompressed(), &chaincfg.MainNetParams, false)
        if err != nil {
            log.Fatal("Failed to generate legacy Bitcoin address:", err)
        }

        segwitAddress, err := publicKeyToAddress(pubKey.SerializeCompressed(), &chaincfg.MainNetParams, true)
        if err != nil {
            log.Fatal("Failed to generate SegWit Bitcoin address:", err)
        }

        // Fast Bloom filter check, then exact match
        if bloomFilter.Test([]byte(legacyAddress)) || bloomFilter.Test([]byte(segwitAddress)) {
            if _, exists := addressMap[legacyAddress]; exists {
                saveAddressData(legacyAddress, segwitAddress, derived)
            } else if _, exists := addressMap[segwitAddress]; exists {
                saveAddressData(legacyAddress, segwitAddress, derived)
            }
        }

        // Progress reporting every 10 million keys
        mutex.Lock()
        counter++
        if counter%10000000 == 0 {
            fmt.Printf("Total keys generated: %d\n", counter)
        }
        mutex.Unlock()
    }
}

// saveAddressData serializes the master key as xprv and saves matching addresses to a file.
// Uses BIP32 fields for serialization.
func saveAddressData(legacyAddress, segwitAddress string, derived []byte) {
    chainCode := derived[32:]
    version := []byte{0x04, 0x88, 0xAD, 0xE4} // Mainnet xprv version
    keyData := append([]byte{0x00}, derived[:32]...) // 0x00 + private key

    depth := byte(0x00)
    parentFingerprint := []byte{0x00, 0x00, 0x00, 0x00}
    childNumber := []byte{0x00, 0x00, 0x00, 0x00}

    xprv := serializeMasterKey(version, depth, parentFingerprint, childNumber, chainCode, keyData)

    // Log and save results
    fmt.Printf("Matching address found!!\n")
    fmt.Printf("Legacy Address: %s\n", legacyAddress)
    fmt.Printf("SegWit Address: %s\n", segwitAddress)
    fmt.Printf("xprv: %s\n", xprv)

    mutex.Lock()
    file, err := os.OpenFile("foundkey.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open file: %v", err)
    }
    _, err = file.WriteString(fmt.Sprintf("Legacy Address: %s\nSegWit Address: %s\nxprv: %s\n", legacyAddress, segwitAddress, xprv))
    if err != nil {
        log.Fatalf("Failed to write to file: %v", err)
    }
    file.Close()
    mutex.Unlock()
}

// main initializes the Bloom filter and address map, then starts key generation workers.
// Waits for all workers to finish (which, in this infinite loop, never happens).
func main() {
    bloomFilter, addressMap = loadAddresses(addressesFile)
    ch := make(chan struct{})

    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go generateKeys(i)
    }

    wg.Wait()
}
