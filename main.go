package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dromara/dongle"
	"golang.org/x/crypto/hkdf"
)

var BMP_HEADER_SIZE = 54
var SALT_SIZE = 32
var START = "1::"
var END = ":>0$"

func byteToBinaryString(value byte) string {
	return strconv.FormatInt(int64(value), 2)
}

func binaryStringToByte(value string) byte {
	char, err := strconv.ParseInt(value, 2, 64)
	if err != nil {
		log.Fatal(err)
	}
	return byte(char)
}

func prng(seed string, imageSize int) uint64 {
	modifyableImageSize := imageSize - BMP_HEADER_SIZE
	hasher := sha256.New()
	hasher.Write([]byte(seed))
	numStr := hex.EncodeToString(hasher.Sum(nil))[0:16]
	num, err := strconv.ParseUint(numStr, 16, 64)

	if err != nil {
		log.Fatal(err)
	}

	return num%uint64(modifyableImageSize) + uint64(BMP_HEADER_SIZE)
}

func startRandomizer(seed string, file []byte) func() uint64 {
	seen := make(map[uint64]bool)
	counter := 0
	var previousPos uint64

	return func() uint64 {
		for {
			imageSize := len(file)
			// This is to make we don't generate the same positions for each image
			uniqueSeed := seed + strconv.FormatUint(previousPos, 10) + "$#" + string(file[:BMP_HEADER_SIZE]) + string(imageSize) + ":" + strconv.Itoa(counter)
			pos := prng(uniqueSeed, imageSize)
			previousPos = pos
			counter++
			if !seen[pos] {
				seen[pos] = true
				return pos
			}
		}
	}
}

func getImage(filename string) (image []byte, err error) {
	if !strings.HasSuffix(filename, ".bmp") {
		return nil, errors.New("Only bmp files are supported")
	}
	file, err := os.ReadFile(filename)

	if err != nil {
		return nil, err
	}
	if len(file) <= BMP_HEADER_SIZE {
		return nil, errors.New("File is too small to be a valid BMP with data.")
	}

	return file, nil
}

func extract(filename string, seed string, salt string) {
	file, err := getImage(filename)

	if err != nil {
		log.Fatalf("Could not get image %w", err)
	}

	getNextPosition := startRandomizer(seed, file)

	byteBuffer := ""
	var messageBytes []byte
	extractedBits := 0
	maxBitsToExtract := len(file) * 8 // Absolute theoretical maximum

	for {
		// Prevent infinite loop if END marker is not found
		if extractedBits > maxBitsToExtract {
			log.Fatal("Extraction limit reached without finding END marker. Seed/Salt likely incorrect or file corrupted.")
		}

		position := getNextPosition()
		binaryStr := byteToBinaryString(file[position])
		byteBuffer += binaryStr[len(binaryStr)-1:]
		extractedBits++

		if len(byteBuffer) == 8 {
			charByte := binaryStringToByte(byteBuffer)
			messageBytes = append(messageBytes, charByte)
			byteBuffer = ""

			messageStr := string(messageBytes)
			if len(messageStr) == len(START) && messageStr != START {
				log.Fatal("Start of the message does not match. Seed/Salt likely incorrect.")
			}
			if strings.HasSuffix(messageStr, END) {
				break
			}
		}
	}
	messageStr := string(messageBytes)

	messageStr = strings.TrimSuffix(messageStr, END)
	messageStr = strings.TrimPrefix(messageStr, START)
	cipher := createAesCipher(file, seed, salt)

	decrypted := dongle.Decrypt.FromHexString(messageStr).ByAes(cipher).ToString()
	fmt.Println("Message:", decrypted)
}

func deriveKeyAndIV(seed string, salt []byte, keyLength int, ivLength int) (key []byte, iv []byte, err error) {
	hkdfReader := hkdf.New(sha256.New, []byte(seed), salt, nil)

	key = make([]byte, keyLength)
	_, err = io.ReadFull(hkdfReader, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	iv = make([]byte, ivLength)
	_, err = io.ReadFull(hkdfReader, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive IV: %w", err)
	}

	return key, iv, nil
}

func generateSalt(fileData []byte, seed string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(seed))
	hash := hasher.Sum(nil)
	salt := hash[:8]

	return append(salt, fileData[:SALT_SIZE]...)
}

func createAesCipher(fileData []byte, seed string, salt string) *dongle.Cipher {
	cipher := dongle.NewCipher()
	cipher.SetMode(dongle.CBC)
	cipher.SetPadding(dongle.PKCS7)

	var saltBytes []byte
	if salt == "" {
		saltBytes = generateSalt(fileData, seed)
		fmt.Println("Generated salt from seed and image header.")
	} else {
		saltBytes = []byte(salt)
		fmt.Println("Using provided salt.")
	}

	if len(saltBytes) < 16 {
		log.Fatal("Generated or provided salt is too short.")
	}

	// divide by half due to hex encoding later
	keyLength := 32 / 2
	ivLength := 16 / 2

	key, iv, err := deriveKeyAndIV(seed, saltBytes, keyLength, ivLength)
	if err != nil {
		log.Fatalf("Failed to derive key/IV: %v", err)
	}

	cipher.SetKey(hex.EncodeToString(key))
	cipher.SetIV(hex.EncodeToString(iv))
	return cipher
}

func embed(inputFile string, outputFile string, secretMessage string, seed string, salt string) {
	file, err := getImage(inputFile)

	if err != nil {
		log.Fatalf("Could not get image %w", err)
	}

	cipher := createAesCipher(file, seed, salt)
	encryptedMessage := dongle.Encrypt.FromString(secretMessage).ByAes(cipher).ToHexString()
	messageBytes := []byte(START + encryptedMessage + END)

	// Convert message bytes to a string of bits
	var bitStringBuilder strings.Builder
	bitStringBuilder.Grow(len(messageBytes) * 8)
	for _, b := range messageBytes {
		bitStringBuilder.WriteString(fmt.Sprintf("%08b", b))
	}
	messageBits := bitStringBuilder.String()

	availableBits := len(file) - BMP_HEADER_SIZE
	if len(messageBits) > availableBits {
		log.Fatalf("Message is too large to embed in this image. Message bits: %d, Available bits: %d", len(messageBits), availableBits)
	}

	getNextPosition := startRandomizer(seed, file)

	fmt.Printf("Embedding %d bits...\n", len(messageBits))
	for _, bit := range messageBits {
		position := getNextPosition()
		binaryStr := byteToBinaryString(file[position])
		newBits := binaryStr[:len(binaryStr)-1] + string(bit)
		file[position] = binaryStringToByte(newBits)
	}
	if err := os.WriteFile(outputFile, file, 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Successfully embedded message into %s\n", outputFile)
}

func main() {
	method := flag.String("method", "", "Method: embed, extract")
	seed := flag.String("seed", "", "Seed for PRNG and key derivation (required for embed/extract)")
	salt := flag.String("salt", "", "[Optional] Salt for key derivation (if not provided, generated from seed+header)")
	inputFile := flag.String("in", "", "Input file (BMP for embed/extract)")
	outputFile := flag.String("out", "", "[Embed] Output BMP file")
	message := flag.String("message", "", "[Embed] Secret message to hide")

	flag.Parse()

	if *method == "extract" {
		extract(*inputFile, *seed, *salt)
	} else if *method == "embed" {
		embed(*inputFile, *outputFile, *message, *seed, *salt)
	}
}
