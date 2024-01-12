package client

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/gob"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"yyakovliev-rgr/utils"
)

var logger = log.New(os.Stdout, "[client]", log.Lshortfile)

func StartClient(wg *sync.WaitGroup) {
	logger.Println("Starting client")
	defer wg.Done()

	// Connect to server
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:443")
	if err != nil {
		logger.Println(err)
		return
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		logger.Println(err)
		return
	}
	defer conn.Close()

	// Create ClientHello message
	clientHello := utils.ClientHelloMsg{
		Random: utils.GenerateRandom(28),
	}

	// Marshal the message into bytes to be sent
	clientHelloBytes := utils.StructToBytes(clientHello)
	logger.Printf("Sending ClientHello with length: %d\n", len(clientHelloBytes))

	// Send ClientHello message bytes
	conn.Write(clientHelloBytes)

	// Receive ServerHello message from server
	var serverHello utils.ServerHelloMsg
	gob.NewDecoder(bufio.NewReader(conn)).Decode(&serverHello)
	logger.Println("Received ServerHello")

	// Parse x509 certificate from data received
	serverCert, err := x509.ParseCertificate(serverHello.Certificate)
	if err != nil {
		logger.Println(err)
		return
	}

	// Read root CA certificate
	caCertPem, err := ioutil.ReadFile("pems/ca-cert.pem")
	if err != nil {
		logger.Println(err)
		return
	}

	// Create certificate pool with root CA certificate
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(caCertPem))
	if !ok {
		logger.Println("failed to parse root certificate")
		return
	}

	// Verification criteria, server certificate must be issued by our CA
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	// Verify server certificate
	if _, err := serverCert.Verify(opts); err != nil {
		logger.Println(err)
		return
	}
	logger.Println("Certificate from server verified by CA")

	// Create random premaster
	premaster := utils.GenerateRandom(48)

	// Typecast RSA public key
	svPubKey, ok := serverCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		logger.Println("Failed to cast cert to rsa.PublicKey")
		return
	}

	// Encrypt premaster
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, svPubKey, premaster, nil)
	if err != nil {
		logger.Println(err)
		return
	}

	// Send encrypted premaster
	conn.Write(ciphertext)
	logger.Println("Sent encrypted premaster:", premaster)

	// Create session key
	sessionKeyBytes := append(clientHello.Random, serverHello.Random...)
	sessionKeyBytes = append(sessionKeyBytes, premaster...)
	h := sha256.New()
	h.Write(sessionKeyBytes)
	sessionKey := h.Sum(nil)
	logger.Println("Created session key:", sessionKey)

	// Encrypt ClientReady message
	clientReadyMsg := utils.EncryptAES([]byte("ClientReady"), sessionKey)

	// Send ClientReady message bytes
	conn.Write(clientReadyMsg)

	// Receive ServerReady message from server
	serverReadyBuf := make([]byte, 1024)
	serverReadyLen, err := conn.Read(serverReadyBuf)
	if err != nil {
		logger.Println(err)
		return
	}

	// Decrypt message and establish connection
	decBytes := utils.DecryptAES(serverReadyBuf[:serverReadyLen], sessionKey)
	if string(decBytes) != "ServerReady" {
		logger.Println("Received something other than ServerReady, something is wrong")
		return
	}
	logger.Println("Established encrypted connection")

	// Read file to be sent over
	testFile, err := ioutil.ReadFile("test.txt")
	if err != nil {
		logger.Println(err)
		return
	}

	// Break file into chunks
	var chunks [][]byte
	chunkSize := 128
	for i := 0; i < len(testFile); i += chunkSize {
		end := i + chunkSize

		if end > len(testFile) {
			end = len(testFile)
		}

		chunks = append(chunks, testFile[i:end])
	}

	// Go through each chunk
	prevHash := make([]byte, 64)
	for i := 0; i < len(chunks); i++ {
		h := make([]byte, 64)
		d := NewShake256()
		d.Write(prevHash)
		logger.Println(string(h))
	}
}
