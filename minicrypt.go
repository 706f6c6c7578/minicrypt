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

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"filippo.io/edwards25519"
)

const maxFileSize = 100 * 1024 * 1024 // 100 MB in Bytes

// Write PEM files
func savePEM(filename string, data []byte, pemType string) error {
	block := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

// Load PEM files
func loadPEM(filename string) ([]byte, error) {
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
	return block.Bytes, nil
}

// Ed25519 to Curve25519 conversions
func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func generateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return privateKey, publicKey, nil
}

// XChaCha20-Poly1305 encryption with random nonce
func encrypt(pubKey ed25519.PublicKey, reader io.Reader, writer io.Writer) error {
	// Check file size
	if seeker, ok := reader.(io.Seeker); ok {
		size, err := seeker.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		_, err = seeker.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		if size > maxFileSize {
			return fmt.Errorf("Message too large!\nPlease use age for file encryption.\nhttps://github.com/FiloSottile/age\n")
		}
	}

	curve25519PubKey, err := ed25519PublicKeyToCurve25519(pubKey)
	if err != nil {
		return err
	}

	// Generate ephemeral key pair
	ephemeralPrivKey, ephemeralPubKey, err := generateKeyPair()
	if err != nil {
		return err
	}
	curve25519EphemeralPrivKey := ed25519PrivateKeyToCurve25519(ephemeralPrivKey)
	curve25519EphemeralPubKey, err := ed25519PublicKeyToCurve25519(ephemeralPubKey)
	if err != nil {
		return err
	}

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(curve25519EphemeralPrivKey, curve25519PubKey)
	if err != nil {
		return err
	}

	// XChaCha20-Poly1305 setup
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return err
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// Read the entire input data to be encrypted
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Encrypt the data
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Prepend the ephemeral public key and nonce to the ciphertext
	finalOutput := append(curve25519EphemeralPubKey, nonce...)
	finalOutput = append(finalOutput, ciphertext...)

	// Encode the output as Base64 and chunk it at 64 characters
	encoded := base64.StdEncoding.EncodeToString(finalOutput)
	_, err = writer.Write([]byte(chunk64(encoded) + "\r\n"))
	return err
}

// XChaCha20-Poly1305 decryption
func decrypt(privKey ed25519.PrivateKey, reader io.Reader, writer io.Writer) error {
	curve25519PrivKey := ed25519PrivateKeyToCurve25519(privKey)

	// Read and decode the input (base64)
	encodedInput, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	decodedInput, err := base64.StdEncoding.DecodeString(string(encodedInput))
	if err != nil {
		return err
	}

	// Extract the ephemeral public key, nonce, and ciphertext
	curve25519EphemeralPubKey := decodedInput[:32]
	nonce := decodedInput[32:56]
	ciphertext := decodedInput[56:]

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(curve25519PrivKey, curve25519EphemeralPubKey)
	if err != nil {
		return err
	}

	// XChaCha20-Poly1305 setup
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return err
	}

	// Decrypt the data
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write the decrypted data
	_, err = writer.Write(plaintext)
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
	if len(os.Args) < 2 {
		fmt.Println("Usage: minicrypt public.pem < infile > outfile")
		fmt.Println("       minicrypt -d private.pem < infile > outfile")
		fmt.Println("       minicrypt -g generate key pair and save it")
		os.Exit(1)
	}

	if os.Args[1] == "-g" {
		// Generate key pair
		priv, pub, err := generateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
			os.Exit(1)
		}
		err = savePEM("public.pem", pub, "PUBLIC KEY")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving public.pem: %v\n", err)
			os.Exit(1)
		}
		err = savePEM("private.pem", priv, "PRIVATE KEY")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private.pem: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key pair successfully generated.")
		os.Exit(0)
	}

	if os.Args[1] == "-d" {
		// Decrypt
		privKeyBytes, err := loadPEM(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
			os.Exit(1)
		}
		privKey := ed25519.PrivateKey(privKeyBytes)
		err = decrypt(privKey, os.Stdin, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Encrypt
		pubKeyBytes, err := loadPEM(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
			os.Exit(1)
		}
		pubKey := ed25519.PublicKey(pubKeyBytes)
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