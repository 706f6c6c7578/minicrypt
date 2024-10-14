package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"filippo.io/edwards25519"
)

const maxMessageSize = 32 * 1024 // 32 KB (32 * 1024 Bytes)

// Write PEM files
func savePEM(filename string, data *memguard.LockedBuffer, pemType string) error {
	block := &pem.Block{
		Type:  pemType,
		Bytes: data.Bytes(),
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

// Load PEM files
func loadPEM(filename string) (*memguard.LockedBuffer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM decoding failed")
	}
	return memguard.NewBufferFromBytes(block.Bytes), nil
}

// Ed25519 to Curve25519 conversions
func ed25519PrivateKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	h := sha512.New()
	h.Write(pk.Bytes()[:32]) // Use only the seed part of the private key
	out := h.Sum(nil)
	return memguard.NewBufferFromBytes(out[:curve25519.ScalarSize]), nil
}

func ed25519PublicKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	p, err := new(edwards25519.Point).SetBytes(pk.Bytes())
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(p.BytesMontgomery()), nil
}

func generateKeyPair() (*memguard.LockedBuffer, *memguard.LockedBuffer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	
	securePrivKey := memguard.NewBufferFromBytes(privateKey)
	securePubKey := memguard.NewBufferFromBytes(publicKey)
	
	return securePrivKey, securePubKey, nil
}

// XChaCha20-Poly1305 encryption with random nonce
func encrypt(pubKey *memguard.LockedBuffer, reader io.Reader, writer io.Writer) error {
	// Read up to maxMessageSize bytes from the reader
	input := make([]byte, maxMessageSize)
	n, err := io.ReadFull(reader, input)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	input = input[:n]

	// Check if there's more data in the reader
	extraByte := make([]byte, 1)
	_, err = reader.Read(extraByte)
	if err == nil {
		return fmt.Errorf("Maximum allowed message size 32 KB!\nPlease use age for file encryption.\nhttps://github.com/FiloSottile/age\n")
	} else if err != io.EOF {
		return err
	}

	curve25519PubKey, err := ed25519PublicKeyToCurve25519(pubKey)
	if err != nil {
		return err
	}
	defer curve25519PubKey.Destroy()

	// Generate ephemeral key pair
	ephemeralPrivKey, ephemeralPubKey, err := generateKeyPair()
	if err != nil {
		return err
	}
	defer ephemeralPrivKey.Destroy()
	defer ephemeralPubKey.Destroy()

	curve25519EphemeralPrivKey, err := ed25519PrivateKeyToCurve25519(ephemeralPrivKey)
	if err != nil {
		return err
	}
	defer curve25519EphemeralPrivKey.Destroy()

	curve25519EphemeralPubKey, err := ed25519PublicKeyToCurve25519(ephemeralPubKey)
	if err != nil {
		return err
	}
	defer curve25519EphemeralPubKey.Destroy()

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(curve25519EphemeralPrivKey.Bytes(), curve25519PubKey.Bytes())
	if err != nil {
		return err
	}
	secureSharedSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSharedSecret.Destroy()

	// XChaCha20-Poly1305 setup
	aead, err := chacha20poly1305.NewX(secureSharedSecret.Bytes())
	if err != nil {
		return err
	}

	// Generate a random nonce
	nonce := memguard.NewBuffer(aead.NonceSize())
	defer nonce.Destroy()
	if _, err := rand.Read(nonce.Bytes()); err != nil {
		return err
	}

	// Encrypt the data
	securePlaintext := memguard.NewBufferFromBytes(input)
	defer securePlaintext.Destroy()

	ciphertext := aead.Seal(nil, nonce.Bytes(), securePlaintext.Bytes(), nil)
	secureCiphertext := memguard.NewBufferFromBytes(ciphertext)
	defer secureCiphertext.Destroy()

	// Prepend the ephemeral public key and nonce to the ciphertext
	finalOutput := memguard.NewBuffer(curve25519EphemeralPubKey.Size() + nonce.Size() + secureCiphertext.Size())
	defer finalOutput.Destroy()

	copy(finalOutput.Bytes(), curve25519EphemeralPubKey.Bytes())
	copy(finalOutput.Bytes()[curve25519EphemeralPubKey.Size():], nonce.Bytes())
	copy(finalOutput.Bytes()[curve25519EphemeralPubKey.Size()+nonce.Size():], secureCiphertext.Bytes())

	// Encode the output as Base64 and chunk it at 64 characters
	encoded := base64.StdEncoding.EncodeToString(finalOutput.Bytes())
	_, err = writer.Write([]byte(chunk64(encoded) + "\r\n"))
	return err
}

// XChaCha20-Poly1305 decryption
func decrypt(privKey *memguard.LockedBuffer, reader io.Reader, writer io.Writer) error {
	curve25519PrivKey, err := ed25519PrivateKeyToCurve25519(privKey)
	if err != nil {
		return err
	}
	defer curve25519PrivKey.Destroy()

	// Read and decode the input (base64)
	encodedInput, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	decodedInput, err := base64.StdEncoding.DecodeString(string(encodedInput))
	if err != nil {
		return err
	}
	secureDecodedInput := memguard.NewBufferFromBytes(decodedInput)
	defer secureDecodedInput.Destroy()

	// Extract the ephemeral public key, nonce, and ciphertext
	curve25519EphemeralPubKey := memguard.NewBuffer(32)
	nonce := memguard.NewBuffer(24)
	ciphertext := memguard.NewBuffer(secureDecodedInput.Size() - 56)
	
	copy(curve25519EphemeralPubKey.Bytes(), secureDecodedInput.Bytes()[:32])
	copy(nonce.Bytes(), secureDecodedInput.Bytes()[32:56])
	copy(ciphertext.Bytes(), secureDecodedInput.Bytes()[56:])

	defer curve25519EphemeralPubKey.Destroy()
	defer nonce.Destroy()
	defer ciphertext.Destroy()

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(curve25519PrivKey.Bytes(), curve25519EphemeralPubKey.Bytes())
	if err != nil {
		return err
	}
	secureSharedSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSharedSecret.Destroy()

	// XChaCha20-Poly1305 setup
	aead, err := chacha20poly1305.NewX(secureSharedSecret.Bytes())
	if err != nil {
		return err
	}

	// Decrypt the data
	plaintext, err := aead.Open(nil, nonce.Bytes(), ciphertext.Bytes(), nil)
	if err != nil {
		return err
	}
	securePlaintext := memguard.NewBufferFromBytes(plaintext)
	defer securePlaintext.Destroy()

	// Write the decrypted data
	_, err = writer.Write(securePlaintext.Bytes())
	return err
}

// Helper function to wrap Base64 output at 64 characters
func chunk64(input string) string {
	var output strings.Builder
	for len(input) > 64 {
		output.WriteString(input[:64] + "\r\n")
		input = input[64:]
	}
	output.WriteString(input)
	return output.String()
}

func main() {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	if len(os.Args) < 2 {
		fmt.Println("Usage: minicrypt public.pem < infile > outfile")
		fmt.Println("       minicrypt -d private.pem < infile > outfile")
		fmt.Println("       minicrypt -g generate key pair and save it")
		os.Exit(1)
	}

	if os.Args[1] == "-g" {
		// Generate key pair
		securePrivKey, securePubKey, err := generateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
			os.Exit(1)
		}
		defer securePrivKey.Destroy()
		defer securePubKey.Destroy()

		err = savePEM("public.pem", securePubKey, "PUBLIC KEY")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving public.pem: %v\n", err)
			os.Exit(1)
		}
		err = savePEM("private.pem", securePrivKey, "PRIVATE KEY")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private.pem: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key pair successfully generated.")
		os.Exit(0)
	}

	if os.Args[1] == "-d" {
		// Decrypt
		privKey, err := loadPEM(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
			os.Exit(1)
		}
		defer privKey.Destroy()

		err = decrypt(privKey, os.Stdin, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Encrypt
		pubKey, err := loadPEM(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
			os.Exit(1)
		}
		defer pubKey.Destroy()

		err = encrypt(pubKey, os.Stdin, os.Stdout)
		if err != nil {
			if strings.Contains(err.Error(), "file size exceeds the maximum allowed size") {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Error encrypting: %v\n", err)
			}
			os.Exit(1)
		}
	}
}
