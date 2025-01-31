package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	_ "github.com/lib/pq"
	"io"
	"log"
)

const (
	host            = "localhost"
	port            = 5432
	user_server     = "postgres"
	user_client     = "client"
	password_server = "123456"
	password_client = "123456"
	dbname          = "encrypted_db"
)

var (
	ckksParams ckks.Parameters
	aesKey     []byte
)

func init() {
	// init CKKS
	var err error
	ckksParams, err = ckks.NewParametersFromLiteral(ckks.PN12QP109)
	if err != nil {
		log.Fatal(err)
	}

	// gen AES key
	aesKey = make([]byte, 32) // 256bit
	_, _ = rand.Read(aesKey)
}

func encryptCKKS(data float64, pk *rlwe.PublicKey) ([]byte, error) {
	encoder := ckks.NewEncoder(ckksParams)
	encryptor := ckks.NewEncryptor(ckksParams, pk)

	plaintext := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, ckksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

func decryptCKKS(data []byte, sk *rlwe.SecretKey) (float64, error) {
	decryptor := ckks.NewDecryptor(ckksParams, sk)
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(data)
	if err != nil {
		return 0, err
	}

	plaintext := decryptor.DecryptNew(ciphertext)
	encoder := ckks.NewEncoder(ckksParams)
	decoded := encoder.Decode(plaintext, ckksParams.LogSlots())

	return real(decoded[0]), nil
}

func encryptAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decryptAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	//init data
	intData := float64(42)
	floatData := 3.14

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user_server, password_server, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//CKKS keys
	ckksSk, ckksPk := ckks.NewKeyGenerator(ckksParams).GenKeyPair()

	//encrypt initial data
	encryptedInt, err := encryptCKKS(intData, ckksPk)
	if err != nil {
		log.Fatal(err)
	}
	encryptedFloat, err := encryptCKKS(floatData, ckksPk)
	if err != nil {
		log.Fatal(err)
	}

	//insert initial data
	_, err = db.Exec("INSERT INTO encrypted_data (encrypted_int, encrypted_float) VALUES ($1, $2)", encryptedInt, encryptedFloat)
	if err != nil {
		log.Fatal(err)
	}

	//-------------CLIENT----------------------------------------------
	retrievedEncryptedInt, retrievedEncryptedFloat := clientSelect()
	//-------------CLIENT----------------------------------------------

	decryptedInt, err := decryptCKKS(retrievedEncryptedInt, ckksSk)
	if err != nil {
		log.Fatal(err)
	}
	decryptedFloat, err := decryptCKKS(retrievedEncryptedFloat, ckksSk)
	if err != nil {
		log.Fatal(err)
	}

	//AES
	encryptedResult, err := encryptAES([]byte(fmt.Sprintf("%f|%f", decryptedInt, decryptedFloat)))
	if err != nil {
		log.Fatal(err)
	}

	//-------------CLIENT-----------------------------------------------
	decryptedResult := clientDecrypt(encryptedResult)
	//-------------CLIENT-----------------------------------------------

	fmt.Println("Initial values:", decryptedInt, decryptedFloat)
	fmt.Println("Decrypted result:", string(decryptedResult))
}

func clientSelect() ([]byte, []byte) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user_client, password_client, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var retrievedEncryptedInt, retrievedEncryptedFloat []byte
	err = db.QueryRow("SELECT encrypted_int, encrypted_float FROM encrypted_data WHERE id = (SELECT MAX(id) FROM encrypted_data)").Scan(&retrievedEncryptedInt, &retrievedEncryptedFloat)
	if err != nil {
		log.Fatal(err)
	}
	return retrievedEncryptedInt, retrievedEncryptedFloat
}

func clientDecrypt(encryptedResult []byte) []byte {
	decryptedResult, err := decryptAES(encryptedResult)
	if err != nil {
		log.Fatal(err)
	}
	return decryptedResult
}
