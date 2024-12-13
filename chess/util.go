package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func EncodeTLV(tag int, uuid string, value []byte) []byte {
	if len(uuid) != 36 {
		panic("UUID doit faire exactement 36 caractères")
	}
	length := 36 + len(value)
	tlv := make([]byte, 4+length)

	tlv[0] = byte(tag >> 8)
	tlv[1] = byte(tag)

	tlv[2] = byte(length >> 8)
	tlv[3] = byte(length)
	copy(tlv[4:4+36], []byte(uuid))
	copy(tlv[4+36:], value)
	return tlv
}

func DecodeTLV(data []byte) (int, string, []byte, error) {
	if len(data) < 4 {
		return 0, "", nil, fmt.Errorf("données TLV trop courtes")
	}
	tag := int(data[0])<<8 | int(data[1])
	length := int(data[2])<<8 | int(data[3])
	if len(data) < 4+length {
		return 0, "", nil, fmt.Errorf("longueur des données TLV incorrecte")
	}
	if length < 36 {
		return 0, "", nil, fmt.Errorf("longueur TLV trop courte pour contenir un UUID")
	}
	uuid := string(data[4 : 4+36])
	value := data[4+36 : 4+length]
	return tag, uuid, value, nil
}

func GenerateUUID() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return ""
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(uuid[0:4]),
		binary.BigEndian.Uint16(uuid[4:6]),
		binary.BigEndian.Uint16(uuid[6:8]),
		binary.BigEndian.Uint16(uuid[8:10]),
		uuid[10:])
}

func GenerateEncryptionKey() []byte {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	return key
}

func GenerateRandomSHA256() string {
	data := make([]byte, 32)
	io.ReadFull(rand.Reader, data)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func EncryptMessage(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création du cipher : %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de GCM : %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la génération du nonce : %v", err)
	}
	return gcm.Seal(nonce, nonce, message, nil), nil
}

func DecryptMessage(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création du cipher : %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de GCM : %v", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext trop court")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func GenerateClientSignature() string {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	if err != nil {
		fmt.Println("[CLIENT] Erreur de génération de la signature :", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
