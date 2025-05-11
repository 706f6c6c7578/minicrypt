package main

import (
    "bufio"
    "bytes"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha512"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/pem"
    "errors"
    "fmt"
    "io"
    "log"
    mrand "math/rand"
    "os"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "time"
    "github.com/awnumar/memguard"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/curve25519"
    "filippo.io/edwards25519"
    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/layout"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/widget"
)

const (
    maxMessageSize = 4096 * 1024
    signatureMarker = "----Ed25519 Signature----"
    uint64Bytes     = 8
    configDirName   = "minicrypt"
    privKeyFile     = "private.pem"
    defaultPadding  = 4096
    separator       = "\n=== MINICRYPT PADDING SEPARATOR ===\n"
    sizePrefix      = "PADDING_SIZE:"
    paddingChars    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ed25519SignatureHexLength = ed25519.SignatureSize * 2
    ed25519PublicKeyHexLength  = ed25519.PublicKeySize * 2
)

var (
    domain = createDomain()
    rng    = mrand.New(mrand.NewSource(time.Now().UnixNano()))
)

type InsufficientInputError struct {
    Msg          string
    RequiredSize int
}
func (e *InsufficientInputError) Error() string {
    return e.Msg
}

func validatePublicKey(content string) error {
    if content == "" {
        return &InsufficientInputError{Msg: "Key content cannot be empty"}
    }

    block, _ := pem.Decode([]byte(content))
    if block == nil || block.Type != "PUBLIC KEY" {
        return errors.New("Not a valid PEM block of type PUBLIC KEY")
    }

    if len(block.Bytes) != ed25519.PublicKeySize {
        return fmt.Errorf("invalid key size: %d bytes (expected %d)", 
            len(block.Bytes), ed25519.PublicKeySize)
    }

    return nil
}

func createDomain() []byte {
    r := []byte{}
    for i := 'A'; i <= 'Z'; i++ {
        r = append(r, byte(i))
    }
    return r
}

func getConfigDir() (string, error) {
    usr, err := os.UserHomeDir()
    if err != nil {
        return "", err
    }
    var configDir string
    switch runtime.GOOS {
    case "windows":
        configDir = filepath.Join(usr, "AppData", "Roaming", configDirName)
    case "darwin":
        configDir = filepath.Join(usr, "Library", "Application Support", configDirName)
    default:
        configDir = filepath.Join(usr, ".config", configDirName)
    }
    if err := os.MkdirAll(configDir, 0700); err != nil {
        return "", err
    }
    return configDir, nil
}

func savePEM(filename string, data *memguard.LockedBuffer, pemType string) error {
    block := &pem.Block{
        Type:  pemType,
        Bytes: data.Bytes(),
    }
    dir := filepath.Dir(filename)
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("could not create directory")
    }
    return os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

func loadPEM(filename string) (*memguard.LockedBuffer, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("Could not read file")
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, errors.New("PEM decoding failed")
    }
    return memguard.NewBufferFromBytes(block.Bytes), nil
}

func loadPrivateKey() (*memguard.LockedBuffer, error) {
    configDir, err := getConfigDir()
    if err != nil {
        return nil, err
    }
    
    pemData, err := os.ReadFile(filepath.Join(configDir, "private.pem"))
    if err != nil {
        return nil, fmt.Errorf("Could not read private.pem: %v", err)
    }

    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "PRIVATE KEY" {
        return nil, errors.New("invalid PEM format for private key")
    }

    return memguard.NewBufferFromBytes(block.Bytes), nil
}

func loadPublicKey(name string) (*memguard.LockedBuffer, error) {
    keyPath, err := getKeyPath(name)
    if err != nil {
        return nil, fmt.Errorf("Could not determine key path: %v", err)
    }

    pemData, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, fmt.Errorf("Could not read file: %v", err)
    }

    if err := validatePublicKey(string(pemData)); err != nil {
        return nil, fmt.Errorf("Validation failed: %v", err)
    }

    block, _ := pem.Decode(pemData)
    return memguard.NewBufferFromBytes(block.Bytes), nil
}

func ed25519PrivateKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
    if pk == nil || pk.Size() != ed25519.PrivateKeySize {
        return nil, errors.New("Invalid private key size")
    }
    h := sha512.New()
    h.Write(pk.Bytes()[:ed25519.SeedSize])
    out := h.Sum(nil)
    return memguard.NewBufferFromBytes(out[:curve25519.ScalarSize]), nil
}

func ed25519PublicKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
    if pk == nil || pk.Size() != ed25519.PublicKeySize {
        return nil, errors.New("Invalid public key size")
    }
    p, err := new(edwards25519.Point).SetBytes(pk.Bytes())
    if err != nil {
        return nil, fmt.Errorf("Invalid public key")
    }
    return memguard.NewBufferFromBytes(p.BytesMontgomery()), nil
}

func generateKeyPair() (*memguard.LockedBuffer, *memguard.LockedBuffer, error) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, fmt.Errorf("Key pair generation failed: %v", err)
    }

    privBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: priv,
    }
    
    pubBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pub,
    }

    privPEM := pem.EncodeToMemory(privBlock)
    pubPEM := pem.EncodeToMemory(pubBlock)

    securePriv := memguard.NewBufferFromBytes(privPEM)
    securePub := memguard.NewBufferFromBytes(pubPEM)

    return securePriv, securePub, nil
}

func encrypt(pubKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {
    if pubKey == nil || pubKey.Size() != ed25519.PublicKeySize {
        return errors.New("Encryption requires a valid public key (32 bytes)")
    }

    data, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("Could not read data: %v", err)
    }

    curvePub, err := ed25519PublicKeyToCurve25519(pubKey)
    if err != nil {
        return fmt.Errorf("Key conversion failed: %v", err)
    }
    defer curvePub.Destroy()

    edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return fmt.Errorf("Could not generate temporary key pair: %v", err)
    }
    ephPriv := memguard.NewBufferFromBytes(edPriv)
    ephPub := memguard.NewBufferFromBytes(edPub)
    defer ephPriv.Destroy()
    defer ephPub.Destroy()

    curveEphPriv, err := ed25519PrivateKeyToCurve25519(ephPriv)
    if err != nil {
        return fmt.Errorf("Ephemeral private key conversion failed: %v", err)
    }
    defer curveEphPriv.Destroy()

    curveEphPub, err := ed25519PublicKeyToCurve25519(ephPub)
    if err != nil {
        return fmt.Errorf("Ephemeral public key conversion failed: %v", err)
    }
    defer curveEphPub.Destroy()

    sharedSecret, err := curve25519.X25519(curveEphPriv.Bytes(), curvePub.Bytes())
    if err != nil {
        return fmt.Errorf("Key exchange failed: %v", err)
    }
    secureSecret := memguard.NewBufferFromBytes(sharedSecret)
    defer secureSecret.Destroy()

    aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
    if err != nil {
        return fmt.Errorf("Could not initialize encryption algorithm: %v", err)
    }

    nonce := memguard.NewBuffer(aead.NonceSize())
    defer nonce.Destroy()
    if _, err := rand.Read(nonce.Bytes()); err != nil {
        return fmt.Errorf("Could not generate nonce: %v", err)
    }

    secureData := memguard.NewBufferFromBytes(data)
    defer secureData.Destroy()
    ciphertext := aead.Seal(nil, nonce.Bytes(), secureData.Bytes(), nil)

    output := bytes.Buffer{}
    output.Write(curveEphPub.Bytes())
    output.Write(nonce.Bytes())
    output.Write(ciphertext)

    encoded := base64.StdEncoding.EncodeToString(output.Bytes())
    _, err = fmt.Fprintln(w, chunk64(encoded))
    return err
}

func decrypt(privKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {
    if privKey == nil {
        return errors.New("Decryption requires a valid private key")
    }
    data, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("Could not read input")
    }
    if bytes.Contains(data, []byte(signatureMarker)) {
        parts := bytes.Split(data, []byte(signatureMarker))
        if len(parts) < 1 {
            return errors.New("invalid signed message format")
        }
        data = bytes.TrimSpace(parts[0])
    }
    decoded, err := base64.StdEncoding.DecodeString(string(data))
    if err != nil {
        return fmt.Errorf("base64 decoding failed: %v", err)
    }
    const headerSize = curve25519.PointSize + chacha20poly1305.NonceSizeX
    if len(decoded) < headerSize {
        return errors.New("message too short")
    }
    secureDecoded := memguard.NewBufferFromBytes(decoded)
    defer secureDecoded.Destroy()
    curvePriv, err := ed25519PrivateKeyToCurve25519(privKey)
    if err != nil {
        return fmt.Errorf("Private key conversion failed")
    }
    defer curvePriv.Destroy()
    ephPub := secureDecoded.Bytes()[:curve25519.PointSize]
    nonce := secureDecoded.Bytes()[curve25519.PointSize : headerSize]
    ciphertext := secureDecoded.Bytes()[headerSize:]
    sharedSecret, err := curve25519.X25519(curvePriv.Bytes(), ephPub)
    if err != nil {
        return fmt.Errorf("Key exchange failed")
    }
    secureSecret := memguard.NewBufferFromBytes(sharedSecret)
    defer secureSecret.Destroy()
    aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
    if err != nil {
        return fmt.Errorf("failed to initialize decryption")
    }
    plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return fmt.Errorf("Decryption failed")
    }
    if _, err := w.Write(plaintext); err != nil {
        return fmt.Errorf("Could not write output")
    }
    return nil
}

func signMessage(keyPath string, r io.Reader, w io.Writer) error {
    privKey, err := loadPEM(keyPath)
    if err != nil {
        return fmt.Errorf("Could not load private key")
    }
    defer privKey.Destroy()
    data, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("Could not read data")
    }
    data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
    data = bytes.TrimSuffix(data, []byte("\r\n"))
    if privKey.Size() != ed25519.PrivateKeySize {
        return errors.New("Invalid private key size")
    }
    signature := ed25519.Sign(privKey.Bytes(), data)
    signatureHex := hex.EncodeToString(signature)
    pubKeyBytes := ed25519.PrivateKey(privKey.Bytes()).Public().(ed25519.PublicKey)
    pubKeyHex := hex.EncodeToString(pubKeyBytes)
    _, err = fmt.Fprintf(w, "%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n",
        string(data),
        signatureMarker,
        signatureHex[:64],
        signatureHex[64:],
        pubKeyHex)
    return err
}

func verifyMessage(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	var data bytes.Buffer
	var sigBlockLines []string
	inSigBlock := false
	dataCollected := false
    var sigHexBuffer bytes.Buffer
    var pubKeyHex string
    var sigHex string

	for scanner.Scan() {
		line := scanner.Text()

		if line == signatureMarker {
			if inSigBlock {
				return errors.New("Unexpected second signature marker found")
			}
			inSigBlock = true
			dataCollected = true
			continue
		}

		if inSigBlock {
			sigBlockLines = append(sigBlockLines, line)
		} else {
			data.WriteString(line)
			data.WriteString("\r\n")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("Error reading input for verification")
	}

	if !inSigBlock {
		return errors.New("Signature marker not found")
	}

	if len(sigBlockLines) < 1 {
        return errors.New("Signature block incomplete")
	}

    pubKeyHex = strings.TrimSpace(sigBlockLines[len(sigBlockLines)-1])
	sigLines := sigBlockLines[:len(sigBlockLines)-1]

	if len(pubKeyHex) != ed25519PublicKeyHexLength {
		return fmt.Errorf("Invalid public key length")
	}

	for _, sigLine := range sigLines {
		trimmedSigLine := strings.TrimSpace(sigLine)
		if len(trimmedSigLine) > 0 {
			sigHexBuffer.WriteString(trimmedSigLine)
		}
	}
	sigHex = sigHexBuffer.String()

	if len(sigHex) != ed25519SignatureHexLength {
		return fmt.Errorf("Invalid total signature length")
	}

	verifiedData := data.Bytes()
	if dataCollected && bytes.HasSuffix(verifiedData, []byte("\r\n")) {
		verifiedData = bytes.TrimSuffix(verifiedData, []byte("\r\n"))
	}

	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("Could not decode public key")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("Invalid public key size")
	}

	signature, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("Could not decode signature")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("Invalid signature size")
	}

	isValid := ed25519.Verify(pubKey, verifiedData, signature)

	if isValid {
		_, err = fmt.Fprintln(w, "Signature is valid")
	} else {
		_, err = fmt.Fprintln(w, "Signature is invalid")
	}

	if err != nil {
		return fmt.Errorf("Could not write verification result")
	}

	return nil
}

func pad(r io.Reader, size int, w io.Writer) error {
    original, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("read error during padding")
    }
    estimatedMetadataSize := len(separator) + len(sizePrefix) + base64.StdEncoding.EncodedLen(uint64Bytes)
    if size < len(original)+estimatedMetadataSize {
        return fmt.Errorf("target size %d too small for content, minimum approx. %d bytes",
            size, len(original)+estimatedMetadataSize)
    }
    paddingNeeded := size - len(original) - estimatedMetadataSize
    if paddingNeeded < 0 {
        return fmt.Errorf("padding error: needed %d padding bytes", paddingNeeded)
    }
    padding := strings.Repeat(paddingChars, paddingNeeded/len(paddingChars)+1)[:paddingNeeded]
    var sizeBytesBuf bytes.Buffer
    sizeBytesBuf.Grow(uint64Bytes)
    err = binary.Write(&sizeBytesBuf, binary.LittleEndian, uint64(paddingNeeded))
    if err != nil {
        return fmt.Errorf("Could not encode padding size")
    }
    sizeBase64 := base64.StdEncoding.EncodeToString(sizeBytesBuf.Bytes())
    sizeMarker := sizePrefix + sizeBase64
    _, err = fmt.Fprintf(w, "%s%s%s%s", original, separator, padding, sizeMarker)
    return err
}

func unpad(r io.Reader) (io.Reader, error) {
    data, err := io.ReadAll(r)
    if err != nil {
        return nil, fmt.Errorf("Read error during unpadding")
    }
    sepIndex := bytes.Index(data, []byte(separator))
    if sepIndex == -1 {
        return nil, errors.New("Invalid format: separator not found")
    }
    remaining := data[sepIndex+len(separator):]
    sizeMarkerIndex := bytes.Index(remaining, []byte(sizePrefix))
    if sizeMarkerIndex == -1 {
        return nil, errors.New("Invalid format: size marker missing")
    }
    sizeDataBase64 := remaining[sizeMarkerIndex+len(sizePrefix):]
    if len(sizeDataBase64) < base64.StdEncoding.EncodedLen(uint64Bytes) {
        return nil, errors.New("Invalid size marker: base64 data too short")
    }
    sizeBytes, err := base64.StdEncoding.DecodeString(string(sizeDataBase64))
    if err != nil {
        return nil, fmt.Errorf("Invalid base64 decoding of size marker")
    }
    if len(sizeBytes) != uint64Bytes {
        return nil, errors.New("Invalid size marker format")
    }
    paddingSize := binary.LittleEndian.Uint64(sizeBytes)
    paddingContent := remaining[:sizeMarkerIndex]
    if len(paddingContent) != int(paddingSize) {
        return nil, fmt.Errorf("Corrupted data")
    }
    expectedTotalLength := sepIndex + len(separator) + int(paddingSize) + len(sizePrefix) + len(sizeDataBase64)
    if len(data) != expectedTotalLength {
        return nil, fmt.Errorf("Corrupted data")
    }
    return bytes.NewReader(data[:sepIndex]), nil
}

func chunk64(s string) string {
    var buf strings.Builder
    const chunkSize = 64
    for len(s) > 0 {
        chunk := s
        if len(s) > chunkSize {
            chunk = s[:chunkSize]
        }
        buf.WriteString(chunk)
        buf.WriteString("\n")
        s = s[len(chunk):]
    }
    return strings.TrimSpace(buf.String())
}

func keyPairExists() (bool, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return false, fmt.Errorf("Could not determine config directory: %v", err)
	}
	privateKeyPath := filepath.Join(configDir, "private.pem")
	publicKeyPath := filepath.Join(configDir, "public.pem")

	privateExists := false
	if _, err := os.Stat(privateKeyPath); err == nil {
		privateExists = true
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("Error checking %s: %v", privateKeyPath, err)
	}

	publicExists := false
	if _, err := os.Stat(publicKeyPath); err == nil {
		publicExists = true
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("Error checking %s: %v", publicKeyPath, err)
	}

	return privateExists && publicExists, nil
}

func processSPE(recipient string, paddingSize int, r io.Reader, w io.Writer) error {
    var signBuffer bytes.Buffer
    privKeyPath, err := getPrivateKeyPath()
    if err != nil {
        return fmt.Errorf("Private key path: %v", err)
    }

    if err := signMessage(privKeyPath, r, &signBuffer); err != nil {
        return fmt.Errorf("Signing failed: %v", err)
    }

    var padBuffer bytes.Buffer
    if err := pad(bytes.NewReader(signBuffer.Bytes()), paddingSize, &padBuffer); err != nil {
        return fmt.Errorf("Padding failed: %v", err)
    }

    pubKeyBuf, err := loadPublicKey(recipient)
    if err != nil {
        return fmt.Errorf("Key loading: %v", err)
    }
    defer pubKeyBuf.Destroy()

    if err := encrypt(pubKeyBuf, bytes.NewReader(padBuffer.Bytes()), w); err != nil {
        return fmt.Errorf("Encryption: %v", err)
    }

    return nil
}

func processDUV(r io.Reader, w io.Writer) error {
	var decryptBuffer bytes.Buffer
	privKey, err := loadPrivateKey()
	if err != nil {
		return fmt.Errorf("Could not load private key", err)
	}
	defer privKey.Destroy()
	if err := decrypt(privKey, r, &decryptBuffer); err != nil {
		return fmt.Errorf("Decryption failed", err)
	}

	unpaddedReader, err := unpad(bytes.NewReader(decryptBuffer.Bytes()))
	if err != nil {
		log.Printf("Unpadding failed, attempting verification of raw data")
		unpaddedReader = bytes.NewReader(decryptBuffer.Bytes())
	}

	var verifyBuffer bytes.Buffer
	if _, err := io.Copy(&verifyBuffer, unpaddedReader); err != nil {
		return fmt.Errorf("Could not copy data to buffer", err)
	}

    if _, err := w.Write(verifyBuffer.Bytes()); err != nil {
        return fmt.Errorf("Could not write decrypted plaintext", err)
    }

	if err := verifyMessage(bytes.NewReader(verifyBuffer.Bytes()), w); err != nil {
		return fmt.Errorf("Verification failed", err)
	}

	return nil
}

func getPrivateKeyPath() (string, error) {
    configDir, err := getConfigDir()
    if err != nil {
        return "", err
    }
    return filepath.Join(configDir, privKeyFile), nil
}

func isCanvasEmpty(text string) bool {
	return strings.TrimSpace(text) == ""
}

func savePublicKey(name, content string) error {
    configDir, err := getConfigDir()
    if err != nil {
        return fmt.Errorf("Could not determine config directory: %v", err)
    }
    
    keyPath := filepath.Join(configDir, name+".pem")
    return os.WriteFile(keyPath, []byte(content), 0600)
}

func showErrorDialog(message string, parent fyne.Window) {
	dialog.ShowError(fmt.Errorf(message), parent)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func publicKeyExists(keyName string) bool {
    keyPath, err := getKeyPath(keyName)
    if err != nil {
        return false
    }

    _, err = os.Stat(keyPath) 
    if err == nil {
        return true
    }
    if os.IsNotExist(err) {
        return false
    }

    return false
}

func savePublicKeyFromContent(name string, content string) error {
    return nil
}

func updateStatus(msg string) {
    fmt.Printf("Status: %s\n", msg)
}

func getKeyPath(name string) (string, error) {
    configDir, err := getConfigDir()
    if err != nil {
        return "", fmt.Errorf("Could not determine config directory: %v", err)
    }

    keyFileName := fmt.Sprintf("%s.pem", name)
    keyPath := filepath.Join(configDir, keyFileName)

    return keyPath, nil
}

func main() {
    os.Setenv("FYNE_DBUS_NO_NOTIFICATIONS", "1")
	memguard.CatchInterrupt()
	defer memguard.Purge()

	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())
	w := a.NewWindow("minicrypt")
	w.Resize(fyne.NewSize(800, 600))
    w.SetOnClosed(func() {
		w.Clipboard().SetContent("")
	})

	textArea := widget.NewMultiLineEntry()
	textArea.SetPlaceHolder("Enter text...")
	textArea.TextStyle = fyne.TextStyle{Monospace: true}
	scrollableTextArea := container.NewScroll(textArea)
	scrollableTextArea.SetMinSize(fyne.NewSize(780, 500))

	statusLabel := widget.NewLabel("Ready.")
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	showCanvasEmptyError := func() {
		statusLabel.SetText("Input field is empty")
		statusLabel.Refresh()
	}

	updateStatus := func(msg string) {
		fyne.Do(func() {
			statusLabel.SetText(msg)
			statusLabel.Refresh()
		})
	}
       
	processOutputAndUpdateGUI := func(outputBuffer *bytes.Buffer, successMsg string) {
		output := outputBuffer.String()
		statusLine := ""
		contentWithoutStatus := output

		validMsg := "Signature is valid"
		invalidMsg := "Signature is invalid"

		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		if len(lines) > 0 {
			lastLine := lines[len(lines)-1]
			if lastLine == validMsg || lastLine == invalidMsg {
				statusLine = lastLine
				if len(lines) > 1 {
				    contentWithoutStatus = strings.Join(lines[:len(lines)-1], "\n")
                } else {
                    contentWithoutStatus = ""
                }
			}
		}

		fyne.Do(func() {
			textArea.SetText(contentWithoutStatus)
			if statusLine != "" {
				statusLabel.SetText(statusLine)
			} else {
				statusLabel.SetText(successMsg)
			}
		})
	}

	speBtn := widget.NewButton("SPE", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}
	updateStatus("SPE: Waiting for parameters...")

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Recipient name (without .pem)")
	paddingEntry := widget.NewEntry()
	paddingEntry.SetPlaceHolder("Padding size (e.g. 4096)")
	paddingEntry.SetText(strconv.Itoa(defaultPadding))

	form := widget.NewForm(
		widget.NewFormItem("Recipient:", recipientEntry),
		widget.NewFormItem("Padding size:", paddingEntry),
	)

	var d dialog.Dialog

	runBtn := widget.NewButton("Execute", func() {
		recipient := recipientEntry.Text
		paddingStr := paddingEntry.Text

		if recipient == "" {
			dialog.ShowError(errors.New("recipient name cannot be empty"), w)
			updateStatus("Recipient name empty")
			return
		}

		paddingSize, err := strconv.Atoi(paddingStr)
		if err != nil || paddingSize <= 0 {
			dialog.ShowError(errors.New("invalid padding size"), w)
			updateStatus("Invalid padding size")
			return
		}

		d.Hide()
		updateStatus("Processing...")

		go func() {
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err := processSPE(recipient, paddingSize, inputReader, outputBuffer)
			if err != nil {
				fmt.Printf("Error in processSPE: %v\n", err)
				updateStatus(fmt.Sprintf("Error: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "SPE successful")
			}
		}()
	})

	cancelBtn := widget.NewButton("Cancel", func() {
		d.Hide()
		updateStatus("SPE canceled")
	})

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		runBtn,
		cancelBtn,
		layout.NewSpacer(),
	)

	content := container.NewVBox(
		form,
		buttonBox,	)

	d = dialog.NewCustomWithoutButtons(
		"SPE Parameters",
		content,
		w,
	)

	d.Resize(fyne.NewSize(400, 180))
	d.Show()
}) 
	duvBtn := widget.NewButton("DUV", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("DUV: Processing...")
		go func() {
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err := processDUV(inputReader, outputBuffer)
			if err != nil {
				dialog.ShowError(err, w)
				updateStatus(fmt.Sprintf("DUV Error: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "DUV successful")
			}
		}()
	})

	signBtn := widget.NewButton("Sign", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("Processing...")
		go func() {
			privKeyPath, err := getPrivateKeyPath()
			if err != nil {
				dialog.ShowError(fmt.Errorf("Could not determine private key path"), w)
				updateStatus(fmt.Sprintf("Signing error"))
				return
			}
			if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
				dialog.ShowError(errors.New("private key not found"), w)
				updateStatus("Private key not found")
				return
			}
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err = signMessage(privKeyPath, inputReader, outputBuffer)
			if err != nil {
				dialog.ShowError(err, w)
				updateStatus(fmt.Sprintf("Signing error"))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "Signing successful")
			}
		}()
	})

	verifyBtn := widget.NewButton("Verify", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}

	updateStatus("Processing...")

	go func() {
		inputReader := bytes.NewReader([]byte(textArea.Text))
		outputBuffer := &bytes.Buffer{}

		err := verifyMessage(inputReader, outputBuffer)
		if err != nil {
			updateStatus(fmt.Sprintf("%v", err))
		} else {
			verificationResult := outputBuffer.String()
			trimmedResult := strings.TrimSpace(verificationResult)
			updateStatus(trimmedResult)
		}
	}()
})

	encryptBtn := widget.NewButton("Encrypt", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}
	updateStatus("Encrypting: Waiting for parameters...")

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Recipient name (without .pem)")

	form := widget.NewForm(
		widget.NewFormItem("Recipient:", recipientEntry),
	)

	var d dialog.Dialog

	runBtn := widget.NewButton("Execute", func() {
		recipient := recipientEntry.Text

		if recipient == "" {
			dialog.ShowError(errors.New("recipient name cannot be empty"), w)
			updateStatus("Recipient name empty")
			return
		}
		d.Hide() 
		updateStatus("Encrypting: Processing...")

		go func() {
			pubKey, err := loadPublicKey(recipient)
			if err != nil {
				updateStatus(fmt.Sprintf("Error loading key: %v", err))
				return
			}
			defer pubKey.Destroy()

			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err = encrypt(pubKey, inputReader, outputBuffer)
			if err != nil {
				updateStatus(fmt.Sprintf("Encryption error: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "Encryption successful")
			}
		}()
	})

	cancelBtn := widget.NewButton("Cancel", func() {
		d.Hide()
		updateStatus("Encryption canceled")
	})

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		runBtn,
		cancelBtn,
		layout.NewSpacer(),
	)

	content := container.NewVBox(
		form,
		buttonBox,
	)

	d = dialog.NewCustomWithoutButtons( 
		"Encryption Parameters",
		content,
		w,
	)

	d.Resize(fyne.NewSize(400, 150))
	d.Show()
})

	decryptBtn := widget.NewButton("Decrypt", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("Decrypting: Processing...")
		go func() {
			privKey, err := loadPrivateKey()
			if err != nil {
				updateStatus(fmt.Sprintf("%v", err))
				return
			}
			defer privKey.Destroy()

			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err = decrypt(privKey, inputReader, outputBuffer)
			if err != nil {
				updateStatus(fmt.Sprintf("%v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "Decryption successful")
			}
		}()
	})

	copyBtn := widget.NewButton("Copy", func() {
        if textArea.Text == "" {
            updateStatus("Input field is empty")
            return
        }
        w.Clipboard().SetContent(textArea.Text)
        updateStatus("Text copied to clipboard")
        })

    pasteBtn := widget.NewButton("Paste", func() {
        content := w.Clipboard().Content()
        if content == "" {
            updateStatus("Clipboard is empty")
            return
        }
        textArea.SetText(content)
        updateStatus("Text pasted from clipboard")
    })

	clearBtn := widget.NewButton("Clear", func() {
		textArea.SetText("")
		w.Clipboard().SetContent("")
		updateStatus("Input field and clipboard cleared")
	})

var importKeyBtn = widget.NewButton("Import", func() {
	updateStatus("Importing Key: Waiting for input...")

	keyContentEntry := widget.NewMultiLineEntry()
	keyContentEntry.SetPlaceHolder("Paste public key PEM content here...")
	keyContentEntry.Wrapping = fyne.TextWrapOff

	keyNameEntry := widget.NewEntry()
	keyNameEntry.SetPlaceHolder("Key Name (e.g., Alice)")

	form := widget.NewForm(
		widget.NewFormItem("Key Content:", keyContentEntry),
		widget.NewFormItem("Name:", keyNameEntry),
	)

	var d dialog.Dialog
	var confirmDialog dialog.Dialog

	saveButton := widget.NewButton("Save", func() {
		keyContent := keyContentEntry.Text
		keyName := keyNameEntry.Text

		if keyName == "" || keyContent == "" {
			showErrorDialog("Name and key content cannot be empty.", w)
			updateStatus("Import failed: Incomplete input.")
			return
		}
		if strings.ToLower(keyName) == "public" {
			showErrorDialog("The name 'public' is not allowed.", w)
			updateStatus("Import failed: Invalid name.")
			return
		}

		if err := validatePublicKey(keyContent); err != nil {
			showErrorDialog("Invalid key content: " + err.Error(), w)
			updateStatus("Import failed: Invalid key format.")
			return
		}

		if publicKeyExists(keyName) {

			confirmContent := container.NewVBox(
				widget.NewLabel(fmt.Sprintf("Key '%s' already exists. Overwrite?", keyName)),
				container.NewHBox(
					widget.NewButton("Cancel", func() {
						confirmDialog.Hide()
						d.Hide()
						updateStatus("Import cancelled.")
					}),
					widget.NewButton("Overwrite", func() {

						if err := savePublicKey(keyName, keyContent); err != nil {
							showErrorDialog("Error overwriting key: " + err.Error(), w)
							updateStatus("Import failed.")
						} else {
							updateStatus(fmt.Sprintf("Key '%s' successfully overwritten.", keyName))
							d.Hide()
						}
						confirmDialog.Hide()
					}),
				),
			)

			confirmDialog = dialog.NewCustomWithoutButtons(
				"Confirmation",
				confirmContent,
				w,
			)
			confirmDialog.Resize(fyne.NewSize(400, 150))
			confirmDialog.Show()

		} else {

			if err := savePublicKey(keyName, keyContent); err != nil {
				showErrorDialog("Error saving key: " + err.Error(), w)
				updateStatus("Import failed.")
			} else {
				updateStatus(fmt.Sprintf("Key '%s' successfully imported.", keyName))
				d.Hide()
			}

		}
	})

	cancelButton := widget.NewButton("Cancel", func() {
		d.Hide()
		updateStatus("Import cancelled.")
	})

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		cancelButton,
		layout.NewSpacer(),
	)

	dialogContent := container.NewVBox(
		form,
		buttonBox,
	)

	d = dialog.NewCustomWithoutButtons(
		"Import Key",
		dialogContent,
		w,
	)
	d.Resize(fyne.NewSize(660, 300))
	d.Show()
})

exportPubKeyBtn := widget.NewButton("Export", func() {
	updateStatus("Exporting Key: Reading public.pem...")
	go func() {
		configDir, err := getConfigDir()
		if err != nil {
			dialog.ShowError(fmt.Errorf("Could not determine configuration directory."), w)
			updateStatus(fmt.Sprintf("Export Error: %v", err))
			return
		}
		pubKeyPath := filepath.Join(configDir, "public.pem")

		contentBytes, err := os.ReadFile(pubKeyPath)
		if os.IsNotExist(err) {
			dialog.ShowError(errors.New("public.pem not found."), w)
			updateStatus("Export Error: public.pem not found.")
			return
		} else if err != nil {
			dialog.ShowError(fmt.Errorf("Could not read public.pem."), w)
			updateStatus(fmt.Sprintf("Export Error.", err))
			return
		}

		keyContentString := string(contentBytes)
		keyDisplayLabel := widget.NewLabel(keyContentString)
		keyDisplayLabel.Wrapping = fyne.TextWrapOff
		keyDisplayLabel.TextStyle = fyne.TextStyle{Monospace: true}

		scrollableKeyDisplay := container.NewScroll(keyDisplayLabel)
		scrollableKeyDisplay.SetMinSize(fyne.NewSize(400, 100))

		copyDialogBtn := widget.NewButton("Copy", func() {
			w.Clipboard().SetContent(keyDisplayLabel.Text)
		})

		var exportDialog dialog.Dialog
		closeDialogBtn := widget.NewButton("Close", func() {
			exportDialog.Hide()
			updateStatus("Export dialog closed.")
		})

		buttonBox := container.NewHBox(
			layout.NewSpacer(),
			copyDialogBtn,
			closeDialogBtn,
			layout.NewSpacer(),
		)

		dialogContent := container.NewVBox(
			widget.NewLabel("Content of public.pem:"),
			scrollableKeyDisplay,
			buttonBox,
		)

		exportDialog = dialog.NewCustomWithoutButtons(
			"Export Public Key",
			dialogContent,
			w,
		)
		exportDialog.Resize(fyne.NewSize(400, 250))
		exportDialog.Show()
		updateStatus("Export: public.pem displayed.")

	}()
})

generateKeypairBtn := widget.NewButton("Generate Keypair", func() {
	updateStatus("Generating Keypair: Checking...")
	go func() {
		exists, err := keyPairExists()
		if err != nil {
			fyne.CurrentApp().SendNotification(&fyne.Notification{
				Title:   "Error",
				Content: fmt.Sprintf("Check failed: %v", err),
			})
			updateStatus(fmt.Sprintf("Error: %v", err))
			return
		}

		var confirmDialog dialog.Dialog

		if exists {
			confirmContent := container.NewVBox(
				widget.NewLabel("A keypair already exists."),
				widget.NewLabel("Do you want to overwrite it?"),
				container.NewHBox(
					layout.NewSpacer(),
					widget.NewButton("Cancel", func() {
						confirmDialog.Hide()
						updateStatus("Cancelled - keeping existing keys")
					}),
					widget.NewButton("Overwrite", func() {
						confirmDialog.Hide()
						updateStatus("Generating new keypair...")

						pub, priv, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							fyne.CurrentApp().SendNotification(&fyne.Notification{
								Title:   "Error",
								Content: fmt.Sprintf("Generation failed: %v", err),
							})
							updateStatus(fmt.Sprintf("Error: %v", err))
							return
						}

						privPEM := pem.EncodeToMemory(&pem.Block{
							Type:  "PRIVATE KEY",
							Bytes: priv,
						})
						pubPEM := pem.EncodeToMemory(&pem.Block{
							Type:  "PUBLIC KEY",
							Bytes: pub,
						})

						configDir, err := getConfigDir()
						if err != nil {
							fyne.CurrentApp().SendNotification(&fyne.Notification{
								Title:   "Error",
								Content: fmt.Sprintf("Configuration directory not found: %v", err),
							})
							return
						}

						if err := os.WriteFile(filepath.Join(configDir, "private.pem"), privPEM, 0600); err != nil {
							fyne.CurrentApp().SendNotification(&fyne.Notification{
								Title:   "Error",
								Content: fmt.Sprintf("Could not save private key: %v", err),
							})
							return
						}

						if err := os.WriteFile(filepath.Join(configDir, "public.pem"), pubPEM, 0600); err != nil {
							fyne.CurrentApp().SendNotification(&fyne.Notification{
								Title:   "Error",
								Content: fmt.Sprintf("Could not save public key: %v", err),
							})
							return
						}

						fyne.CurrentApp().SendNotification(&fyne.Notification{
							Title:   "Success",
							Content: "New keypair generated and saved",
						})
						updateStatus(fmt.Sprintf("New keypair saved in %s", configDir))
					}),
					layout.NewSpacer(),
				),
			)

			confirmDialog = dialog.NewCustomWithoutButtons(
				"Confirmation",
				confirmContent,
				w,
			)
			confirmDialog.Resize(fyne.NewSize(400, 150))
			confirmDialog.Show()
		} else {
			updateStatus("Generating initial keypair...")

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				fyne.CurrentApp().SendNotification(&fyne.Notification{
					Title:   "Error",
					Content: fmt.Sprintf("Generation failed: %v", err),
				})
				updateStatus(fmt.Sprintf("Error: %v", err))
				return
			}

			privPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: priv,
			})
			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pub,
			})

			configDir, err := getConfigDir()
			if err != nil {
				fyne.CurrentApp().SendNotification(&fyne.Notification{
					Title:   "Error",
					Content: fmt.Sprintf("Configuration directory not found: %v", err),
				})
				return
			}

			if err := os.WriteFile(filepath.Join(configDir, "private.pem"), privPEM, 0600); err != nil {
				fyne.CurrentApp().SendNotification(&fyne.Notification{
					Title:   "Error",
					Content: fmt.Sprintf("Could not save private key: %v", err),
				})
				return
			}

			if err := os.WriteFile(filepath.Join(configDir, "public.pem"), pubPEM, 0600); err != nil {
				fyne.CurrentApp().SendNotification(&fyne.Notification{
					Title:   "Error",
					Content: fmt.Sprintf("Could not save public key: %v", err),
				})
				return
			}

			fyne.CurrentApp().SendNotification(&fyne.Notification{
				Title:   "Success",
				Content: "Keypair successfully generated",
			})
			updateStatus(fmt.Sprintf("Initial keypair saved in %s", configDir))
		}
	}()
})

	topButtons := container.NewCenter(
		container.NewHBox(
			speBtn,
			duvBtn,
			widget.NewSeparator(),
			signBtn,
			verifyBtn,
			widget.NewSeparator(),
			encryptBtn,
			decryptBtn,
		),
	)

	bottomLeftButtons := container.NewCenter(
		container.NewHBox(
			copyBtn,
			pasteBtn,
			clearBtn,
		),
	)

	bottomRightButtons := container.NewHBox(
		importKeyBtn,
		exportPubKeyBtn,
		generateKeypairBtn,
	)

	bottomButtons := container.NewHBox(
		bottomLeftButtons,
		layout.NewSpacer(),
		bottomRightButtons,
	)

	content := container.NewVBox(
		topButtons,
		scrollableTextArea,
		bottomButtons,
		statusLabel,
	)

	w.SetContent(content)
	w.ShowAndRun()
}