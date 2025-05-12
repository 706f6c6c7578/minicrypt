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
	uint64Bytes = 8
	configDirName = "minicrypt"
	privKeyFile = "private.pem"
	defaultPadding = 4096
	separator = "\n=== MINICRYPT PADDING SEPARATOR ===\n"
	sizePrefix = "PADDING_SIZE:"
	paddingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ed25519SignatureHexLength = ed25519.SignatureSize * 2
	ed25519PublicKeyHexLength = ed25519.PublicKeySize * 2
)

var (
	domain = createDomain()
	rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
)

type InsufficientInputError struct {
	Msg string
	RequiredSize int
}

func (e *InsufficientInputError) Error() string {
	return e.Msg
}

func validatePublicKey(content string) error {
	if content == "" {
		return &InsufficientInputError{Msg: "Schlüsselinhalt darf nicht leer sein"}
	}
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("kein gültiger PEM-Block vom Typ PUBLIC KEY")
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return fmt.Errorf("ungültige Schlüsselgröße: %d Bytes (erwartet %d)", len(block.Bytes), ed25519.PublicKeySize)
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
		Type: pemType,
		Bytes: data.Bytes(),
	}
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("Verzeichnis konnte nicht erstellt werden.")
	}
	return os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

func loadPEM(filename string) (*memguard.LockedBuffer, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Datei konnte nicht gelesen werden.")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM-Decodierung fehlgeschlagen.")
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
		return nil, fmt.Errorf("private.pem konnte nicht gelesen werden: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("ungültiges PEM-Format für privaten Schlüssel")
	}
	return memguard.NewBufferFromBytes(block.Bytes), nil
}

func loadPublicKey(name string) (*memguard.LockedBuffer, error) {
	keyPath, err := getKeyPath(name)
	if err != nil {
		return nil, fmt.Errorf("Schlüsselpfad konnte nicht ermittelt werden: %v", err)
	}
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("Datei konnte nicht gelesen werden: %v", err)
	}
	if err := validatePublicKey(string(pemData)); err != nil {
		return nil, fmt.Errorf("validierung fehlgeschlagen: %v", err)
	}
	block, _ := pem.Decode(pemData)
	return memguard.NewBufferFromBytes(block.Bytes), nil
}

func getPrivateKeyPath() (string, error) {
    configDir, err := getConfigDir()
    if err != nil {
        return "", err
    }
    return filepath.Join(configDir, "private.pem"), nil
}

func ed25519PrivateKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if pk == nil || pk.Size() != ed25519.PrivateKeySize {
		return nil, errors.New("ungültige Größe des geheimen Schlüssels.")
	}
	h := sha512.New()
	h.Write(pk.Bytes()[:ed25519.SeedSize])
	out := h.Sum(nil)
	return memguard.NewBufferFromBytes(out[:curve25519.ScalarSize]), nil
}

func ed25519PublicKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if pk == nil || pk.Size() != ed25519.PublicKeySize {
		return nil, errors.New("ungültige Größe des öffentlichen Schlüssels.")
	}
	p, err := new(edwards25519.Point).SetBytes(pk.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ungültiger öffentlicher Schlüssel.")
	}
	return memguard.NewBufferFromBytes(p.BytesMontgomery()), nil
}

func generateKeyPair() (*memguard.LockedBuffer, *memguard.LockedBuffer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Erzeugung des Schlüsselpaars fehlgeschlagen: %v", err)
	}
	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: priv}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pub}
	privPEM := pem.EncodeToMemory(privBlock)
	pubPEM := pem.EncodeToMemory(pubBlock)
	securePriv := memguard.NewBufferFromBytes(privPEM)
	securePub := memguard.NewBufferFromBytes(pubPEM)
	return securePriv, securePub, nil
}

func encrypt(pubKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {
	if pubKey == nil || pubKey.Size() != ed25519.PublicKeySize {
		return errors.New("Verschlüsselung erfordert einen gültigen öffentlichen Schlüssel (32 Bytes)")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("Daten konnten nicht gelesen werden: %v", err)
	}
	secureData := memguard.NewBufferFromBytes(data)
	defer secureData.Destroy()

	curvePub, err := ed25519PublicKeyToCurve25519(pubKey)
	if err != nil {
		return fmt.Errorf("Schlüsselkonvertierung fehlgeschlagen: %v", err)
	}
	defer curvePub.Destroy()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("temporäres Schlüsselpaar konnte nicht erzeugt werden: %v", err)
	}
	ephPriv := memguard.NewBufferFromBytes(edPriv)
	ephPub := memguard.NewBufferFromBytes(edPub)
	defer ephPriv.Destroy()
	defer ephPub.Destroy()

	curveEphPriv, err := ed25519PrivateKeyToCurve25519(ephPriv)
	if err != nil {
		return fmt.Errorf("Konvertierung des ephemeren privaten Schlüssels fehlgeschlagen: %v", err)
	}
	defer curveEphPriv.Destroy()

	curveEphPub, err := ed25519PublicKeyToCurve25519(ephPub)
	if err != nil {
		return fmt.Errorf("Konvertierung des ephemeren öffentlichen Schlüssels fehlgeschlagen: %v", err)
	}
	defer curveEphPub.Destroy()

	sharedSecret, err := curve25519.X25519(curveEphPriv.Bytes(), curvePub.Bytes())
	if err != nil {
		return fmt.Errorf("Schlüsselaustausch fehlgeschlagen: %v", err)
	}
	secureSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSecret.Destroy()

	aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
	if err != nil {
		return fmt.Errorf("Verschlüsselungsalgorithmus konnte nicht initialisiert werden: %v", err)
	}

	nonce := memguard.NewBuffer(aead.NonceSize())
	defer nonce.Destroy()
	if _, err := rand.Read(nonce.Bytes()); err != nil {
		return fmt.Errorf("Nonce konnte nicht generiert werden: %v", err)
	}

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
		return errors.New("Entschlüsselung benötigt gültigen geheimen Schlüssel.")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("Eingabe konnte nicht gelesen werden.")
	}
	if bytes.Contains(data, []byte(signatureMarker)) {
		parts := bytes.Split(data, []byte(signatureMarker))
		if len(parts) < 1 {
			return errors.New("Ungültiges Format der signierten Nachricht.")
		}
		data = bytes.TrimSpace(parts[0])
	}
	secureData := memguard.NewBufferFromBytes(data)
	defer secureData.Destroy()

	decoded, err := base64.StdEncoding.DecodeString(string(secureData.Bytes()))
	if err != nil {
		return fmt.Errorf("base64-Dekodierung fehlgeschlagen: %v", err)
	}
	const headerSize = curve25519.PointSize + chacha20poly1305.NonceSizeX
	if len(decoded) < headerSize {
		return errors.New("Nachricht zu kurz.")
	}

	curvePriv, err := ed25519PrivateKeyToCurve25519(privKey)
	if err != nil {
		return fmt.Errorf("Konvertierung des geheimen Schlüssels fehlgeschlagen.")
	}
	defer curvePriv.Destroy()

	ephPub := decoded[:curve25519.PointSize]
	nonce := decoded[curve25519.PointSize:headerSize]
	ciphertext := decoded[headerSize:]

	sharedSecret, err := curve25519.X25519(curvePriv.Bytes(), ephPub)
	if err != nil {
		return fmt.Errorf("Schlüsselaustausch fehlgeschlagen.")
	}
	secureSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSecret.Destroy()

	aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
	if err != nil {
		return fmt.Errorf("Initialisierung der Entschlüsselung fehlgeschlagen.")
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("Entschlüsselung fehlgeschlagen.")
	}
	securePlaintext := memguard.NewBufferFromBytes(plaintext)
	defer securePlaintext.Destroy()

	if _, err := w.Write(securePlaintext.Bytes()); err != nil {
		return fmt.Errorf("Ausgabe konnte nicht geschrieben werden.")
	}
	return nil
}

func signMessage(keyPath string, r io.Reader, w io.Writer) error {
    privKey, err := loadPEM(keyPath)
    if err != nil {
        return fmt.Errorf("Geheimer Schlüssel konnte nicht geladen werden.")
    }
    defer privKey.Destroy()

    data, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("Daten konnten nicht gelesen werden.")
    }

    data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
    
    data = []byte(strings.ToValidUTF8(string(data), ""))
    
    if bytes.HasSuffix(data, []byte("\r\n")) {
        data = data[:len(data)-2]
    }
    
    secureData := memguard.NewBufferFromBytes(data)
    defer secureData.Destroy()

    signature := ed25519.Sign(privKey.Bytes(), secureData.Bytes())
    secureSignature := memguard.NewBufferFromBytes(signature)
    defer secureSignature.Destroy()

    signatureHex := hex.EncodeToString(secureSignature.Bytes())
    pubKeyBytes := ed25519.PrivateKey(privKey.Bytes()).Public().(ed25519.PublicKey)
    pubKeyHex := hex.EncodeToString(pubKeyBytes)

    _, err = fmt.Fprintf(w, "%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n",
        string(secureData.Bytes()),
        signatureMarker,
        signatureHex[:64],
        signatureHex[64:],
        pubKeyHex)
    return err
}

func verifyMessage(r io.Reader, w io.Writer) error {
    data, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("lesefehler: %v", err)
    }

    data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
    
    secureData := memguard.NewBufferFromBytes(data)
    defer secureData.Destroy()

    scanner := bufio.NewScanner(bytes.NewReader(secureData.Bytes()))
    var messageBuffer bytes.Buffer
    var sigBlockLines []string
    inSigBlock := false

    for scanner.Scan() {
        line := scanner.Text()
        if line == signatureMarker {
            inSigBlock = true
            continue
        }
        if inSigBlock {
            sigBlockLines = append(sigBlockLines, line)
        } else {
            messageBuffer.WriteString(line)
            messageBuffer.WriteString("\r\n")
        }
    }

    messageBytes := messageBuffer.Bytes()
    if bytes.HasSuffix(messageBytes, []byte("\r\n")) {
        messageBytes = messageBytes[:len(messageBytes)-2]
    }

    secureMessage := memguard.NewBufferFromBytes(messageBytes)
    defer secureMessage.Destroy()

    if !inSigBlock {
        return errors.New("signatur-marker nicht gefunden")
    }

    if len(sigBlockLines) < 3 {
        return errors.New("signaturblock unvollständig")
    }

    pubKeyHex := sigBlockLines[len(sigBlockLines)-1]
    sigHex := sigBlockLines[0] + sigBlockLines[1]

    pubKey, err := hex.DecodeString(pubKeyHex)
    if err != nil {
        return fmt.Errorf("öffentlicher schlüssel konnte nicht dekodiert werden")
    }

    securePubKey := memguard.NewBufferFromBytes(pubKey)
    defer securePubKey.Destroy()

    signature, err := hex.DecodeString(sigHex)
    if err != nil {
        return fmt.Errorf("signatur konnte nicht dekodiert werden")
    }

    secureSignature := memguard.NewBufferFromBytes(signature)
    defer secureSignature.Destroy()

    isValid := ed25519.Verify(securePubKey.Bytes(), secureMessage.Bytes(), secureSignature.Bytes())
    
    if isValid {
        _, err = fmt.Fprintln(w, "Signatur ist gültig.")
    } else {
        _, err = fmt.Fprintln(w, "Signatur ist ungültig.")
    }

    return err
}

func pad(r io.Reader, size int, w io.Writer) error {
	original, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("Lesefehler während des Aufpolstern.")
	}
	estimatedMetadataSize := len(separator) + len(sizePrefix) + base64.StdEncoding.EncodedLen(uint64Bytes)
	if size < len(original)+estimatedMetadataSize {
		return fmt.Errorf("Zielgröße %d zu klein für den Inhalt, Minimum ca. %d Bytes.",
			size, len(original)+estimatedMetadataSize)
	}
	paddingNeeded := size - len(original) - estimatedMetadataSize
	if paddingNeeded < 0 {
		return fmt.Errorf("Aufpolster Fehler: benötigte %d Aufpolster-Bytes", paddingNeeded)
	}
	padding := strings.Repeat(paddingChars, paddingNeeded/len(paddingChars)+1)[:paddingNeeded]
	var sizeBytesBuf bytes.Buffer
	sizeBytesBuf.Grow(uint64Bytes)
	err = binary.Write(&sizeBytesBuf, binary.LittleEndian, uint64(paddingNeeded))
	if err != nil {
		return fmt.Errorf("Aufpolster-Größe konnte nicht kodiert werden.")
	}
	sizeBase64 := base64.StdEncoding.EncodeToString(sizeBytesBuf.Bytes())
	sizeMarker := sizePrefix + sizeBase64
	_, err = fmt.Fprintf(w, "%s%s%s%s", original, separator, padding, sizeMarker)
	return err
}

func unpad(r io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("Lesefehler während des Zurücksetzens.")
	}
	sepIndex := bytes.Index(data, []byte(separator))
	if sepIndex == -1 {
		return nil, errors.New("Ungültiges Format: Separator nicht gefunden.")
	}
	remaining := data[sepIndex+len(separator):]
	sizeMarkerIndex := bytes.Index(remaining, []byte(sizePrefix))
	if sizeMarkerIndex == -1 {
		return nil, errors.New("ungültiges Format: Größen-Marker fehlt.")
	}
	sizeDataBase64 := remaining[sizeMarkerIndex+len(sizePrefix):]
	if len(sizeDataBase64) < base64.StdEncoding.EncodedLen(uint64Bytes) {
		return nil, errors.New("Ungültiger Größen-Marker: Base64-Daten zu kurz")
	}
	sizeBytes, err := base64.StdEncoding.DecodeString(string(sizeDataBase64))
	if err != nil {
		return nil, fmt.Errorf("Ungültige base64-Dekodierung des Größen-Markers.")
	}
	if len(sizeBytes) != uint64Bytes {
		return nil, errors.New("Ungültiges Format des Größen-Markers.")
	}
	paddingSize := binary.LittleEndian.Uint64(sizeBytes)
	paddingContent := remaining[:sizeMarkerIndex]
	if len(paddingContent) != int(paddingSize) {
		return nil, fmt.Errorf("Beschädigte Daten.")
	}
	expectedTotalLength := sepIndex + len(separator) + int(paddingSize) + len(sizePrefix) + len(sizeDataBase64)
	if len(data) != expectedTotalLength {
		return nil, fmt.Errorf("Beschädigte Daten.")
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
		return false, fmt.Errorf("Konfigurationsverzeichnis konnte nicht ermittelt werden: %v", err)
	}
	privateKeyPath := filepath.Join(configDir, "private.pem")
	publicKeyPath := filepath.Join(configDir, "public.pem")

	privateExists := false
	if _, err := os.Stat(privateKeyPath); err == nil {
		privateExists = true
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("Fehler beim Prüfen von %s: %v", privateKeyPath, err)
	}

	publicExists := false
	if _, err := os.Stat(publicKeyPath); err == nil {
		publicExists = true
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("Fehler beim Prüfen von %s: %v", publicKeyPath, err)
	}

	return privateExists && publicExists, nil
}

func processSPE(recipient string, paddingSize int, r io.Reader, w io.Writer) error {
    inputData, err := io.ReadAll(r)
    if err != nil {
        return fmt.Errorf("lesefehler: %v", err)
    }
    
    inputData = bytes.ReplaceAll(inputData, []byte("\r\n"), []byte("\n"))
    inputData = bytes.ReplaceAll(inputData, []byte("\n"), []byte("\r\n"))
    
    inputData = []byte(strings.ToValidUTF8(string(inputData), ""))
    
    secureInput := memguard.NewBufferFromBytes(inputData)
    defer secureInput.Destroy()

    var signBuffer bytes.Buffer
    privKeyPath, err := getPrivateKeyPath()
    if err != nil {
        return fmt.Errorf("privater schlüsselpfad: %v", err)
    }

    if err := signMessage(privKeyPath, bytes.NewReader(secureInput.Bytes()), &signBuffer); err != nil {
        return fmt.Errorf("signieren: %v", err)
    }

    secureSignedData := memguard.NewBufferFromBytes(signBuffer.Bytes())
    defer secureSignedData.Destroy()

    var padBuffer bytes.Buffer
    if err := pad(bytes.NewReader(secureSignedData.Bytes()), paddingSize, &padBuffer); err != nil {
        return fmt.Errorf("padding: %v", err)
    }

    securePaddedData := memguard.NewBufferFromBytes(padBuffer.Bytes())
    defer securePaddedData.Destroy()

    pubKeyBuf, err := loadPublicKey(recipient)
    if err != nil {
        return fmt.Errorf("schlüsselladung: %v", err)
    }
    defer pubKeyBuf.Destroy()

    if err := encrypt(pubKeyBuf, bytes.NewReader(securePaddedData.Bytes()), w); err != nil {
        return fmt.Errorf("verschlüsselung: %v", err)
    }

    return nil
}

func processDUV(r io.Reader, w io.Writer) error {
    var decryptBuffer bytes.Buffer
    privKey, err := loadPrivateKey()
    if err != nil {
        return fmt.Errorf("Geheimer Schlüssel konnte nicht geladen werden: %v", err)
    }
    defer privKey.Destroy()

    if err := decrypt(privKey, r, &decryptBuffer); err != nil {
        return fmt.Errorf("Entschlüsselung fehlgeschlagen: %v", err)
    }

    unpaddedReader, err := unpad(bytes.NewReader(decryptBuffer.Bytes()))
    if err != nil {
        return fmt.Errorf("Zurücksetzen des Paddings fehlgeschlagen: %v", err)
    }

    var verifyBuffer bytes.Buffer
    if _, err := io.Copy(&verifyBuffer, unpaddedReader); err != nil {
        return fmt.Errorf("Daten konnten nicht in den Buffer kopiert werden: %v", err)
    }

    data := bytes.ReplaceAll(verifyBuffer.Bytes(), []byte("\r\n"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
    
    secureBuffer := memguard.NewBufferFromBytes(data)
    defer secureBuffer.Destroy()

    if _, err := w.Write(secureBuffer.Bytes()); err != nil {
        return fmt.Errorf("Entschlüsselter Klartext konnte nicht geschrieben werden: %v", err)
    }

    if err := verifyMessage(bytes.NewReader(secureBuffer.Bytes()), w); err != nil {
        return fmt.Errorf("Verifizierung fehlgeschlagen: %v", err)
    }

    return nil
}

func isCanvasEmpty(text string) bool {
	return strings.TrimSpace(text) == ""
}

func savePublicKey(name, content string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("Konfigurationsverzeichnis konnte nicht ermittelt werden: %v", err)
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
		return "", fmt.Errorf("Konfigurationsverzeichnis konnte nicht ermittelt werden: %v", err)
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
	textArea.SetPlaceHolder("Text eingeben ...")
	textArea.TextStyle = fyne.TextStyle{Monospace: true}
	scrollableTextArea := container.NewScroll(textArea)
	scrollableTextArea.SetMinSize(fyne.NewSize(780, 500))

	statusLabel := widget.NewLabel("Bereit.")
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}


	showCanvasEmptyError := func() {
		statusLabel.SetText("Eingabefeld ist leer.")
		statusLabel.Refresh()
	}

	updateStatus := func(msg string) {
		fyne.Do(func() {
			statusLabel.SetText(msg)
			statusLabel.Refresh()
		})
	}
       
	processOutputAndUpdateGUI := func(outputBuffer *bytes.Buffer, successMsg string) {
		output := string(outputBuffer.Bytes())
		statusLine := ""
		contentWithoutStatus := output

		validMsg := "Signatur ist gültig"
		invalidMsg := "Signatur ist ungültig"

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

	speBtn := widget.NewButton("SAV", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}
	updateStatus("SAV: Warte auf Parameter...")

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Empfängername (ohne .pem)")
	paddingEntry := widget.NewEntry()
	paddingEntry.SetPlaceHolder("Aufpolster-Größe (z.B. 4096)")
	paddingEntry.SetText(strconv.Itoa(defaultPadding))

	form := widget.NewForm(
		widget.NewFormItem("Empfänger:", recipientEntry),
		widget.NewFormItem("Aufpolster-Größe:", paddingEntry),
	)

	var d dialog.Dialog

	runBtn := widget.NewButton("Ausführen", func() {
		recipient := recipientEntry.Text
		paddingStr := paddingEntry.Text

		if recipient == "" {
			dialog.ShowError(errors.New("Empfängername darf nicht leer sein"), w)
			updateStatus("Empfängername leer.")
			return
		}

		paddingSize, err := strconv.Atoi(paddingStr)
		if err != nil || paddingSize <= 0 {
			dialog.ShowError(errors.New("Ungültige Aufpolster-Größe."), w)
			updateStatus("Ungültige Aufpolster-Größe.")
			return
		}

		d.Hide()
		updateStatus("Verarbeite...")

		go func() {
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err := processSPE(recipient, paddingSize, inputReader, outputBuffer)
			if err != nil {
				fmt.Printf("Error in processSPE: %v\n", err)
				updateStatus(fmt.Sprintf("Fehler: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "SAV erfolgreich.")
			}
		}()
	})

	cancelBtn := widget.NewButton("Abbrechen", func() {
		d.Hide()
		updateStatus("SAV abgebrochen.")
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
		"SAV Parameter",
		content,
		w,
	)

	d.Resize(fyne.NewSize(400, 180))
	d.Show()
}) 
	duvBtn := widget.NewButton("EZV", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("EZV: Verarbeite...")
		go func() {
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err := processDUV(inputReader, outputBuffer)
			if err != nil {
				dialog.ShowError(err, w)
				updateStatus(fmt.Sprintf("EZV Fehler: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "EZV erfolgreich.")
			}
		}()
	})

		signBtn := widget.NewButton("Signieren", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("Verarbeite...")
		go func() {
			privKeyPath, err := getPrivateKeyPath()
			if err != nil {
				dialog.ShowError(fmt.Errorf("Pfad zum geheimen Schlüssel konnte nicht ermittelt werden."), w)
				updateStatus(fmt.Sprintf("Signier-Fehler."))
				return
			}
			if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
				dialog.ShowError(errors.New("Geheimen Schlüssel nicht gefunden."), w)
				updateStatus("Geheimen Shhlüsselnicht gefunden.")
				return
			}
			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err = signMessage(privKeyPath, inputReader, outputBuffer)
			if err != nil {
				dialog.ShowError(err, w)
				updateStatus(fmt.Sprintf("Signier-Fehler."))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "Signatur erfolgreich.")
			}
		}()
	})

	verifyBtn := widget.NewButton("Verifizieren", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}

	updateStatus("Verarbeite...")

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

	encryptBtn := widget.NewButton("Verschlüsseln", func() {
	if isCanvasEmpty(textArea.Text) {
		showCanvasEmptyError()
		return
	}
	updateStatus("Verschlüssele: Warte auf Parameter...")

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Empfängername (ohne .pem)")

	form := widget.NewForm(
		widget.NewFormItem("Empfänger:", recipientEntry),
	)

	var d dialog.Dialog

	runBtn := widget.NewButton("Ausführen", func() {
		recipient := recipientEntry.Text

		if recipient == "" {
			dialog.ShowError(errors.New("Empfängername darf nicht leer sein"), w)
			updateStatus("Empfängername leer.")
			return
		}
		d.Hide() 
		updateStatus("Verschlüssele: Verarbeite...")

		go func() {
			pubKey, err := loadPublicKey(recipient)
			if err != nil {
				updateStatus(fmt.Sprintf("Fehler beim Laden des Schlüssels: %v", err))
				return
			}
			defer pubKey.Destroy()

			inputReader := bytes.NewReader([]byte(textArea.Text))
			outputBuffer := &bytes.Buffer{}
			err = encrypt(pubKey, inputReader, outputBuffer)
			if err != nil {
				updateStatus(fmt.Sprintf("Verschlüsselungsfehler: %v", err))
			} else {
				processOutputAndUpdateGUI(outputBuffer, "Verschlüsselung erfolgreich.")
			}
		}()
	})

	cancelBtn := widget.NewButton("Abbrechen", func() {
		d.Hide()
		updateStatus("Verschlüsselung abgebrochen.")
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
		"Verschlüsselungs-Parameter",
		content,
		w,
	)

	d.Resize(fyne.NewSize(400, 150))
	d.Show()
})

	decryptBtn := widget.NewButton("Entschlüsseln", func() {
		if isCanvasEmpty(textArea.Text) {
			showCanvasEmptyError()
			return
		}
		updateStatus("Entschlüssele: Verarbeite...")
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
				processOutputAndUpdateGUI(outputBuffer, "Entschlüsselung erfolgreich.")
			}
		}()
	})

	copyBtn := widget.NewButton("Kopieren", func() {
            if textArea.Text == "" {
                updateStatus("Eingabefeld ist leer.")
                return
        }
        w.Clipboard().SetContent(textArea.Text)
        updateStatus("Text in Zwischenablage kopiert.")
        })

        pasteBtn := widget.NewButton("Einfügen", func() {
            content := w.Clipboard().Content()
            if content == "" {
                updateStatus("Zwischenablage ist leer.")
                return
             }
             textArea.SetText(content)
             updateStatus("Text aus Zwischenablage eingefügt.")
        })

	clearBtn := widget.NewButton("Leeren", func() {
		textArea.SetText("")
		w.Clipboard().SetContent("")
		updateStatus("Eingabefeld und Zwischenablage geleert.")
	})

var importKeyBtn = widget.NewButton("Importieren", func() {
	updateStatus("Importiere Schlüssel: Warte auf Eingabe...")

	keyContentEntry := widget.NewMultiLineEntry()
	keyContentEntry.SetPlaceHolder("Öffentlicher Schlüssel PEM-Inhalt hier einfügen...")
	keyContentEntry.Wrapping = fyne.TextWrapOff

	keyNameEntry := widget.NewEntry()
	keyNameEntry.SetPlaceHolder("Schlüsselname (z.B. Alice)")

	form := widget.NewForm(
		widget.NewFormItem("Schlüsselinhalt:", keyContentEntry),
		widget.NewFormItem("Name:", keyNameEntry),
	)

	var d dialog.Dialog
	var confirmDialog dialog.Dialog

	saveButton := widget.NewButton("Speichern", func() {
		keyContent := keyContentEntry.Text
		keyName := keyNameEntry.Text

		if keyName == "" || keyContent == "" {
			showErrorDialog("Name und Schlüsselinhalt dürfen nicht leer sein.", w)
			updateStatus("Import fehlgeschlagen: Eingabe unvollständig.")
			return
		}
		if strings.ToLower(keyName) == "public" {
			showErrorDialog("Der Name 'public' ist nicht erlaubt.", w)
			updateStatus("Import fehlgeschlagen: Ungültiger Name.")
			return		}

		if err := validatePublicKey(keyContent); err != nil {
			showErrorDialog("Ungültiger Schlüsselinhalt: " + err.Error(), w)
			updateStatus("Import fehlgeschlagen: Ungültiger Schlüsselformat.")
			return
		}

		if publicKeyExists(keyName) {

			confirmContent := container.NewVBox(
				widget.NewLabel(fmt.Sprintf("Schlüssel '%s' existiert bereits. Überschreiben?", keyName)),
				container.NewHBox(
					widget.NewButton("Abbrechen", func() {
						confirmDialog.Hide()
						d.Hide()
						updateStatus("Importieren abgebrochen.")
					}),
						widget.NewButton("Überschreiben", func() {
						
						if err := savePublicKey(keyName, keyContent); err != nil {
							 showErrorDialog("Fehler beim Überschreiben des Schlüssels: " + err.Error(), w)
							 updateStatus("Import fehlgeschlagen.")
						} else {
							 updateStatus(fmt.Sprintf("Schlüssel '%s' erfolgreich überschrieben.", keyName))							 					
							 d.Hide()
						}
							confirmDialog.Hide()
					}),
				),
			)

			confirmDialog = dialog.NewCustomWithoutButtons(
				"Bestätigung",
				confirmContent,
				w,
			)
			confirmDialog.Resize(fyne.NewSize(400, 150))
			confirmDialog.Show()

		} else {
	
			if err := savePublicKey(keyName, keyContent); err != nil {
				 showErrorDialog("Fehler beim Speichern des Schlüssels: " + err.Error(), w)
				 updateStatus("Import fehlgeschlagen.") 			} else {
				 updateStatus(fmt.Sprintf("Schlüssel '%s' erfolgreich importiert.", keyName)) 
				 d.Hide() 			
                        }
			
		}
	})

		cancelButton := widget.NewButton("Abbrechen", func() {
		d.Hide()
		updateStatus("Importieren abgebrochen.")
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
		"Schlüssel importieren",
		dialogContent, 
		w,
	)
	d.Resize(fyne.NewSize(660, 300))
	d.Show()
}) 

exportPubKeyBtn := widget.NewButton("Exportieren", func() {
	updateStatus("Exportiere Schlüssel: Lese public.pem...")
	go func() {
		configDir, err := getConfigDir()
		if err != nil {
			dialog.ShowError(fmt.Errorf("Konfigurationsverzeichnis konnte nicht ermittelt werden."), w)
			updateStatus(fmt.Sprintf("Export-Fehler: %v", err))
			return
		}
		pubKeyPath := filepath.Join(configDir, "public.pem")

		contentBytes, err := os.ReadFile(pubKeyPath)
		if os.IsNotExist(err) {
			dialog.ShowError(errors.New("public.pem nicht gefunden."), w)
			updateStatus("Export-Fehler: public.pem nicht gefunden.")
			return
		} else if err != nil {
			dialog.ShowError(fmt.Errorf("public.pem konnte nicht gelesen werden."), w)
			updateStatus(fmt.Sprintf("Export-Fehler.", err))
			return
		}

		keyContentString := string(contentBytes)
		keyDisplayLabel := widget.NewLabel(keyContentString)
		keyDisplayLabel.Wrapping = fyne.TextWrapOff 
		keyDisplayLabel.TextStyle = fyne.TextStyle{Monospace: true}

		scrollableKeyDisplay := container.NewScroll(keyDisplayLabel)
		scrollableKeyDisplay.SetMinSize(fyne.NewSize(400, 100))

		copyDialogBtn := widget.NewButton("Kopieren", func() {
			w.Clipboard().SetContent(keyDisplayLabel.Text)
		})

		var exportDialog dialog.Dialog
		closeDialogBtn := widget.NewButton("Schließen", func() {
			exportDialog.Hide()
			updateStatus("Export-Dialog geschlossen.")		
		})

			buttonBox := container.NewHBox(
			layout.NewSpacer(), 
			copyDialogBtn,
			closeDialogBtn,
			layout.NewSpacer(),
		)

		dialogContent := container.NewVBox(
			widget.NewLabel("Inhalt von public.pem:"),
			scrollableKeyDisplay,
			buttonBox,		)

			exportDialog = dialog.NewCustomWithoutButtons(
			"Öffentlichen Schlüssel exportieren",
			dialogContent,
			w,
		)
		exportDialog.Resize(fyne.NewSize(400, 250))
		exportDialog.Show()
		updateStatus("Export: public.pem angezeigt.")

	}() 
})

generateKeypairBtn := widget.NewButton("Schlüsselpaar erzeugen", func() {
    updateStatus("Erzeuge Schlüsselpaar: Prüfe...")
    go func() {
        exists, err := keyPairExists()
        if err != nil {
            fyne.CurrentApp().SendNotification(&fyne.Notification{
                Title:   "Fehler",
                Content: fmt.Sprintf("Prüfung fehlgeschlagen: %v", err),
            })
            updateStatus(fmt.Sprintf("Fehler: %v", err))
            return
        }

        var confirmDialog dialog.Dialog

        if exists {
            confirmContent := container.NewVBox(
                widget.NewLabel("Ein Schlüsselpaar existiert bereits."),
                widget.NewLabel("Möchten Sie es überschreiben?"),
                container.NewHBox(
                    layout.NewSpacer(),
                    widget.NewButton("Abbrechen", func() {
                        confirmDialog.Hide()
                        updateStatus("Abgebrochen - bestehende Schlüssel behalten")
                    }),
                    widget.NewButton("Überschreiben", func() {
                        confirmDialog.Hide()
                        updateStatus("Erzeuge neues Schlüsselpaar...")

                        pub, priv, err := ed25519.GenerateKey(rand.Reader)
                        if err != nil {
                            fyne.CurrentApp().SendNotification(&fyne.Notification{
                                Title:   "Fehler",
                                Content: fmt.Sprintf("Generierung fehlgeschlagen: %v", err),
                            })
                            updateStatus(fmt.Sprintf("Fehler: %v", err))
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
                                Title:   "Fehler",
                                Content: fmt.Sprintf("Konfigurationsverzeichnis nicht gefunden: %v", err),
                            })
                            return
                        }

                        if err := os.WriteFile(filepath.Join(configDir, "private.pem"), privPEM, 0600); err != nil {
                            fyne.CurrentApp().SendNotification(&fyne.Notification{
                                Title:   "Fehler",
                                Content: fmt.Sprintf("Private Key konnte nicht gespeichert werden: %v", err),
                            })
                            return
                        }

                        if err := os.WriteFile(filepath.Join(configDir, "public.pem"), pubPEM, 0600); err != nil {
                            fyne.CurrentApp().SendNotification(&fyne.Notification{
                                Title:   "Fehler",
                                Content: fmt.Sprintf("Public Key konnte nicht gespeichert werden: %v", err),
                            })
                            return
                        }

                        fyne.CurrentApp().SendNotification(&fyne.Notification{
                            Title:   "Erfolg",
                            Content: "Neues Schlüsselpaar wurde erzeugt und gespeichert",
                        })
                        updateStatus(fmt.Sprintf("Neues Schlüsselpaar in %s gespeichert", configDir))
                    }),
                    layout.NewSpacer(),
                ),
            )

            confirmDialog = dialog.NewCustomWithoutButtons(
                "Bestätigung",
                confirmContent,
                w,
            )
            confirmDialog.Resize(fyne.NewSize(400, 150))
            confirmDialog.Show()
        } else {
            updateStatus("Erzeuge initiales Schlüsselpaar...")
            
            pub, priv, err := ed25519.GenerateKey(rand.Reader)
            if err != nil {
                fyne.CurrentApp().SendNotification(&fyne.Notification{
                    Title:   "Fehler",
                    Content: fmt.Sprintf("Generierung fehlgeschlagen: %v", err),
                })
                updateStatus(fmt.Sprintf("Fehler: %v", err))
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
                    Title:   "Fehler",
                    Content: fmt.Sprintf("Konfigurationsverzeichnis nicht gefunden: %v", err),
                })
                return
            }

            if err := os.WriteFile(filepath.Join(configDir, "private.pem"), privPEM, 0600); err != nil {
                fyne.CurrentApp().SendNotification(&fyne.Notification{
                    Title:   "Fehler",
                    Content: fmt.Sprintf("Private Key konnte nicht gespeichert werden: %v", err),
                })
                return
            }

            if err := os.WriteFile(filepath.Join(configDir, "public.pem"), pubPEM, 0600); err != nil {
                fyne.CurrentApp().SendNotification(&fyne.Notification{
                    Title:   "Fehler",
                    Content: fmt.Sprintf("Public Key konnte nicht gespeichert werden: %v", err),
                })
                return
            }

            fyne.CurrentApp().SendNotification(&fyne.Notification{
                Title:   "Erfolg",
                Content: "Schlüsselpaar erfolgreich erzeugt",
            })
            updateStatus(fmt.Sprintf("Initiales Schlüsselpaar in %s gespeichert", configDir))
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