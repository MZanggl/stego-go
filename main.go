package main

import (
	"crypto/sha256"
	"encoding/hex"
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
var FINISH = "<<END>>"
var START = "GO:"

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

func startRandomizer(seed string, imageSize int) func() uint64 {
	seen := make(map[uint64]bool)
	counter := 0
	var previousPos uint64

	return func() uint64 {
		for {
			pos := prng(seed+strconv.FormatUint(previousPos, 10)+":"+strconv.Itoa(counter), imageSize)
			previousPos = pos
			counter++
			if !seen[pos] {
				seen[pos] = true
				return pos
			}
		}
	}
}

func extract(filename string, seed string) {
	if !strings.HasSuffix(filename, ".bmp") {
		log.Fatal("Only bmp files are supported", filename)
	}
	file, err := os.ReadFile(filename)

	if err != nil {
		log.Fatal(err)
	}

	getNextPosition := startRandomizer(seed, len(file))

	byteBuffer := ""
	var messageBytes []byte

	for {
		position := getNextPosition()
		binaryStr := byteToBinaryString(file[position])
		byteBuffer += binaryStr[len(binaryStr)-1:]

		if len(byteBuffer) == 8 {
			charByte := binaryStringToByte(byteBuffer)
			messageBytes = append(messageBytes, charByte)
			byteBuffer = ""

			messageStr := string(messageBytes)
			if len(messageStr) == len(START) && messageStr != START {
				log.Fatal("Start of the message does not match. Seed likely incorrect.")
			}
			if strings.Contains(messageStr, FINISH) {
				break
			}
		}
	}
	messageStr := string(messageBytes)

	messageStr = strings.TrimSuffix(messageStr, FINISH)
	messageStr = strings.TrimPrefix(messageStr, START)
	cipher := createAesCipher(file, seed)

	decrypted := dongle.Decrypt.FromHexString(messageStr).ByAes(cipher).ToString()
	fmt.Println("Message:", decrypted)
}

func deriveKeyAndIV(seed string, salt []byte, keyLength int, ivLength int) (key []byte, iv []byte, err error) {
	hkdfReader := hkdf.New(sha256.New, []byte(seed), salt, nil)

	key = make([]byte, keyLength)
	_, err = io.ReadFull(hkdfReader, key)
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, ivLength)
	_, err = io.ReadFull(hkdfReader, iv)
	if err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

func createAesCipher(fileData []byte, seed string) *dongle.Cipher {
	cipher := dongle.NewCipher()
	cipher.SetMode(dongle.CBC)
	cipher.SetPadding(dongle.PKCS7)

	hasher := sha256.New()
	hasher.Write([]byte(seed))
	hash := hasher.Sum(nil)
	salt := hash[:8]

	salt = append(salt, fileData[:SALT_SIZE]...)
	// divide by half due to hex encoding later
	keyLength := 32 / 2
	ivLength := 16 / 2

	key, iv, err := deriveKeyAndIV(seed, salt, keyLength, ivLength)
	if err != nil {
		log.Fatal(err)
	}
	cipher.SetKey(hex.EncodeToString(key))
	cipher.SetIV(hex.EncodeToString(iv))
	return cipher
}

func embed(inputFile string, outputFile string, secretMessage string, seed string) {
	if !strings.HasSuffix(inputFile, ".bmp") {
		log.Fatal("Only bmp files are supported")
	}
	file, err := os.ReadFile(inputFile)

	if err != nil {
		log.Fatal(err)
	}

	cipher := createAesCipher(file, seed)
	encryptedMessage := dongle.Encrypt.FromString(secretMessage).ByAes(cipher).ToHexString()
	messageBytes := []byte(START + encryptedMessage + FINISH)

	var builder strings.Builder
	for _, b := range messageBytes {
		builder.WriteString(fmt.Sprintf("%08b", b))
	}
	message := builder.String()

	getNextPosition := startRandomizer(seed, len(file))
	for _, bit := range message {
		position := getNextPosition()
		binaryStr := byteToBinaryString(file[position])
		newBits := binaryStr[:len(binaryStr)-1] + string(bit)
		file[position] = binaryStringToByte(newBits)
	}
	if err := os.WriteFile(outputFile, file, 0666); err != nil {
		log.Fatal(err)
	}
}

func main() {
	method := flag.String("method", "", "Method to run: embed or extract")
	seed := flag.String("seed", "", "PRNG seed")
	inputFile := flag.String("in", "", "Input BMP file to write message into")
	outputFile := flag.String("out", "", "Output BMP file with hidden message")
	message := flag.String("message", "", "Message to hide")

	flag.Parse()

	fmt.Println("Start", *method)
	if *method == "extract" {
		extract(*inputFile, *seed)
	} else if *method == "embed" {
		embed(*inputFile, *outputFile, *message, *seed)
	}
	fmt.Println("Finished", *method)
}
