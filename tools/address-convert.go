// address-convert.go converts Bitcoin addresses to Hash160 values for faster brute force comparison.
// This preprocesses the addresses.txt file to create address-hashes.txt with raw Hash160 values.
// Input: ../add	fmt.Println("\n📊 Address Type Breakdown:")
// Output: ../address-hashes.txt (20-byte Hash160 values, binary format)

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	inputFile  = "../addresses.txt"
	outputFile = "../address-hashes.bin"
)

// addressToHash160 converts a Bitcoin address to its Hash160 value
func addressToHash160(address string) ([]byte, error) {
	// Basic validation first
	if len(address) < 25 || len(address) > 90 {
		return nil, fmt.Errorf("invalid address length: %d", len(address))
	}

	// Decode the address using btcutil
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		// Check for common malformed address patterns
		if strings.Contains(err.Error(), "unsupported witness version") {
			return nil, fmt.Errorf("malformed witness address (invalid version): %s", address)
		}
		if strings.Contains(err.Error(), "unsupported witness program length") {
			return nil, fmt.Errorf("malformed witness address (invalid length): %s", address)
		}
		return nil, fmt.Errorf("failed to decode address %s: %v", address, err)
	}

	// Extract Hash160 based on address type
	switch a := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		// P2PKH address (starts with "1")
		return a.Hash160()[:], nil
	case *btcutil.AddressWitnessPubKeyHash:
		// P2WPKH address (starts with "bc1q" and is 42 chars)
		return a.Hash160()[:], nil
	case *btcutil.AddressScriptHash:
		// P2SH address (starts with "3") - less common in brute force lists
		return a.Hash160()[:], nil
	case *btcutil.AddressWitnessScriptHash:
		// P2WSH address (starts with "bc1q" and is 62 chars) - SegWit Script Hash
		// Note: These have 32-byte script hashes, not 20-byte Hash160
		// For brute force purposes, we'll use the first 20 bytes to fit our format
		scriptHash := a.WitnessProgram()
		if len(scriptHash) >= 20 {
			return scriptHash[:20], nil
		}
		return scriptHash, nil
	case *btcutil.AddressTaproot:
		// P2TR address (starts with "bc1p") - Taproot addresses
		// These have 32-byte Taproot outputs, we'll use first 20 bytes
		taprootHash := a.WitnessProgram()
		if len(taprootHash) >= 20 {
			return taprootHash[:20], nil
		}
		return taprootHash, nil
	default:
		return nil, fmt.Errorf("unsupported address type: %T for address %s", addr, address)
	}
}

func main() {
	fmt.Println("🔄 Bitcoin Address to Hash160 Converter")
	fmt.Println("=======================================")
	fmt.Printf("Input file: %s\n", inputFile)
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Println()

	startTime := time.Now()

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	var processedCount int64
	var errorCount int64
	var duplicateCount int64
	var malformedCount int64 // Invalid/corrupted addresses
	var p2pkhCount int64     // Legacy addresses (1...)
	var p2wpkhCount int64    // SegWit pubkey hash (bc1q... 42 chars)
	var p2shCount int64      // Script hash (3...)
	var p2wshCount int64     // SegWit script hash (bc1q... 62 chars)
	var p2trCount int64      // Taproot (bc1p...)

	// Track duplicates using a map
	seenHashes := make(map[string]bool)

	fmt.Println("Processing addresses...")

	for scanner.Scan() {
		address := strings.TrimSpace(scanner.Text())
		if address == "" {
			continue // Skip empty lines
		}

		// Check if address is brute-forceable before processing
		isBruteForceableAddr := false
		if strings.HasPrefix(address, "1") {
			// P2PKH - brute-forceable
			isBruteForceableAddr = true
			p2pkhCount++
		} else if strings.HasPrefix(address, "3") {
			// P2SH - NOT brute-forceable (requires script)
			p2shCount++
		} else if strings.HasPrefix(address, "bc1q") {
			if len(address) == 42 {
				// P2WPKH - brute-forceable
				isBruteForceableAddr = true
				p2wpkhCount++
			} else if len(address) == 62 {
				// P2WSH - NOT brute-forceable (requires script)
				p2wshCount++
			}
		} else if strings.HasPrefix(address, "bc1p") {
			// P2TR - brute-forceable (key-path spending)
			isBruteForceableAddr = true
			p2trCount++
		}

		// Skip non-brute-forceable addresses
		if !isBruteForceableAddr {
			errorCount++
			continue
		}

		// Convert address to Hash160 (only for brute-forceable addresses)
		hash160, err := addressToHash160(address)
		if err != nil {
			// Categorize different types of errors
			if strings.Contains(err.Error(), "malformed") {
				malformedCount++
				// Only log first few malformed addresses to avoid spam
				if malformedCount <= 10 {
					log.Printf("Malformed address #%d: %s", malformedCount, address)
				}
			} else {
				log.Printf("Error processing address %s: %v", address, err)
			}
			errorCount++
			continue
		} // Check for duplicates
		hashStr := string(hash160)
		if seenHashes[hashStr] {
			duplicateCount++
			continue
		}
		seenHashes[hashStr] = true

		// Write the 20-byte Hash160 to output file
		_, err = outFile.Write(hash160)
		if err != nil {
			log.Fatalf("Failed to write hash to output file: %v", err)
		}

		processedCount++

		// Progress indicator every 1M addresses
		if processedCount%1000000 == 0 {
			elapsed := time.Since(startTime)
			rate := float64(processedCount) / elapsed.Seconds()
			fmt.Printf("Processed %dM addresses (%.0f addresses/sec)\n",
				processedCount/1000000, rate)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}

	elapsed := time.Since(startTime)

	fmt.Println("\n✅ Conversion Complete!")
	fmt.Println("========================")
	totalInput := processedCount + errorCount
	skippedNonBruteForce := p2shCount + p2wshCount
	fmt.Printf("Total addresses read: %d\n", totalInput+skippedNonBruteForce)
	fmt.Printf("Brute-forceable addresses: %d\n", totalInput)
	fmt.Printf("Successfully converted: %d\n", processedCount)
	fmt.Printf("Skipped (non-brute-forceable): %d\n", skippedNonBruteForce)
	fmt.Printf("Errors encountered: %d\n", errorCount)
	if malformedCount > 0 {
		fmt.Printf("  - Malformed/corrupted: %d\n", malformedCount)
		fmt.Printf("  - Other errors: %d\n", errorCount-malformedCount)
	}
	fmt.Printf("Duplicates skipped: %d\n", duplicateCount)
	fmt.Printf("Unique Hash160 values: %d\n", processedCount)
	fmt.Printf("Processing time: %v\n", elapsed)
	fmt.Printf("Average rate: %.0f addresses/sec\n", float64(totalInput)/elapsed.Seconds())
	fmt.Printf("Output file size: %d bytes (%.2f MB)\n",
		processedCount*20, float64(processedCount*20)/(1024*1024))

	fmt.Println("\n� Address Type Breakdown:")
	fmt.Printf("- P2PKH (1...):           %d (%.1f%%)\n", p2pkhCount, float64(p2pkhCount)/float64(processedCount+errorCount)*100)
	fmt.Printf("- P2WPKH (bc1q... 42ch):  %d (%.1f%%)\n", p2wpkhCount, float64(p2wpkhCount)/float64(processedCount+errorCount)*100)
	fmt.Printf("- P2SH (3...):            %d (%.1f%%)\n", p2shCount, float64(p2shCount)/float64(processedCount+errorCount)*100)
	fmt.Printf("- P2WSH (bc1q... 62ch):   %d (%.1f%%)\n", p2wshCount, float64(p2wshCount)/float64(processedCount+errorCount)*100)
	fmt.Printf("- P2TR (bc1p...):         %d (%.1f%%)\n", p2trCount, float64(p2trCount)/float64(processedCount+errorCount)*100)

	fmt.Println("\n�💡 Usage Notes:")
	fmt.Printf("- Original file: %d addresses (~%.1f MB text)\n",
		processedCount+errorCount, float64(processedCount+errorCount*34)/(1024*1024))
	fmt.Printf("- Hash160 file: %d hashes (%.2f MB binary)\n",
		processedCount, float64(processedCount*20)/(1024*1024))
	fmt.Printf("- Space savings: %.1f%% smaller\n",
		(1.0-float64(processedCount*20)/float64(processedCount*34))*100)
	fmt.Println("- Ready for brute force optimization! 🚀")
	fmt.Printf("- Note: P2WSH and P2TR use truncated hashes (first 20 bytes)\n")
}
