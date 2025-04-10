# stego-go

Hide messages in BMP images using steganography. stego-go uses a pseudo-random number generator (PRNG) based on a secret seed to randomly select pixel bits for embedding the hidden message. The message is first encrypted using AES and then encoded into the least significant bits (LSBs) of the image's pixel data. 

## Embed Message

```bash
go run main.go -method="embed" -in="./images/raw.bmp" -out="./images/embedded.bmp" -seed="my secret seed" -message="my hidden message😊"
```

## Extract Message
```bash
go run main.go -method="extract" -in="./images/embedded.bmp" -seed="my secret seed"
# output: my hidden message😊
```