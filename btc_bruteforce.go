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
	numWorkers    = 16
	errorRate     = 0.000000001
	addressesFile = "addresses.txt"
)

var (
	bloomFilter *bloom.BloomFilter
	addressMap  map[string]struct{}
	wg          sync.WaitGroup
	mutex       sync.Mutex
	counter     int
)

func loadAddresses(filePath string) (*bloom.BloomFilter, map[string]struct{}) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

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
	addressMap := make(map[string]struct{}) // Local variable

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

func serializeMasterKey(version []byte, depth byte, parentFingerprint []byte, childNumber []byte, chainCode []byte, key []byte) string {
	data := append(version, depth)
	data = append(data, parentFingerprint...)
	data = append(data, childNumber...)
	data = append(data, chainCode...)
	checksum := sha256.Sum256(data)
	checksum = sha256.Sum256(checksum[:])
	data = append(data, checksum[:4]...)
	return base58.Encode(data)
}

func generateKeys(workerID int, ch chan struct{}) {
	defer wg.Done()

	for {
		seed := make([]byte, 16)
		_, err := rand.Read(seed)
		if err != nil {
			log.Fatal("Failed to generate seed:", err)
		}

		hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
		hmac512.Write(seed)
		derived := hmac512.Sum(nil)

		masterPrivateKey := derived[:32]
		privKey, _ := btcec.PrivKeyFromBytes(masterPrivateKey)
		pubKey := privKey.PubKey()

		legacyAddress, err := publicKeyToAddress(pubKey.SerializeCompressed(), &chaincfg.MainNetParams, false)
		if err != nil {
			log.Fatal("Failed to generate legacy Bitcoin address:", err)
		}

		segwitAddress, err := publicKeyToAddress(pubKey.SerializeCompressed(), &chaincfg.MainNetParams, true)
		if err != nil {
			log.Fatal("Failed to generate SegWit Bitcoin address:", err)
		}

		// Check if either address is in the Bloom filter
		if bloomFilter.Test([]byte(legacyAddress)) || bloomFilter.Test([]byte(segwitAddress)) {
			// Exact address match check
			if _, exists := addressMap[legacyAddress]; exists {
				// Generate xprv and save if exact match in addressMap
				saveAddressData(legacyAddress, segwitAddress, derived)
			} else if _, exists := addressMap[segwitAddress]; exists {
				// Generate xprv and save if exact match in addressMap
				saveAddressData(legacyAddress, segwitAddress, derived)
			}
		}

		// Update the shared counter
		mutex.Lock()
		counter++
		if counter%10000000 == 0 {
			fmt.Printf("Total keys generated: %d\n", counter)
		}
		mutex.Unlock()
	}
}

func saveAddressData(legacyAddress, segwitAddress string, derived []byte) {
	chainCode := derived[32:]
	version := []byte{0x04, 0x88, 0xAD, 0xE4}
	keyData := append([]byte{0x00}, derived[:32]...)

	depth := byte(0x00)
	parentFingerprint := []byte{0x00, 0x00, 0x00, 0x00}
	childNumber := []byte{0x00, 0x00, 0x00, 0x00}

	xprv := serializeMasterKey(version, depth, parentFingerprint, childNumber, chainCode, keyData)

	// Log the results and save to file
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

func main() {
	bloomFilter, addressMap = loadAddresses(addressesFile) // Assign to global variables
	ch := make(chan struct{})

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go generateKeys(i, ch)
	}

	wg.Wait()
}
