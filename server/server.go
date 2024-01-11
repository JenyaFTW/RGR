package server

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"yyakovliev-rgr/utils"
)

var logger = log.New(os.Stdout, "[server]", log.Lshortfile)

func handleRequest(conn net.Conn) {
	defer conn.Close()

	// Receive ClientHello message from client
	var clientHello utils.ClientHelloMsg
	gob.NewDecoder(bufio.NewReader(conn)).Decode(&clientHello)
	logger.Println("Received ClientHello")

	// Read server certificate from PEM file
	r, err := ioutil.ReadFile("pems/server-cert.pem")
	if err != nil {
		logger.Println(err)
		return
	}
	block, _ := pem.Decode(r)

	// Create ServerHello message containing server certificate
	serverHello := utils.ServerHelloMsg{
		Random:      utils.GenerateRandom(28),
		Certificate: block.Bytes,
	}
	serverHelloBytes := utils.StructToBytes(serverHello)

	// Send ServerHello message to client
	conn.Write(serverHelloBytes)
	logger.Println("Sent ServerHello")

	// Receive encrypted premaster from client
	pmBuf := make([]byte, 256)
	_, err = conn.Read(pmBuf)
	if err != nil {
		logger.Println(err)
		return
	}

	// Read server private key
	svKeyPem, err := ioutil.ReadFile("pems/server-key.pem")
	if err != nil {
		logger.Println(err)
		return
	}
	svKeyBlock, _ := pem.Decode(svKeyPem)
	svKey, err := x509.ParsePKCS8PrivateKey(svKeyBlock.Bytes)
	if err != nil {
		logger.Println(err)
		return
	}

	// Typecast RSA private key
	svPrivKey, ok := svKey.(*rsa.PrivateKey)
	if !ok {
		logger.Println("Failed to cast cert to rsa.PrivateKey")
		return
	}

	// Decrypt premaster
	hash := sha512.New()
	premaster, err := rsa.DecryptOAEP(hash, rand.Reader, svPrivKey, pmBuf, nil)
	if err != nil {
		logger.Println(err)
		return
	}
	logger.Println("Decrypted premaster:", premaster)

	// Create session key
	sessionKeyBytes := append(clientHello.Random, serverHello.Random...)
	sessionKeyBytes = append(sessionKeyBytes, premaster...)
	h := sha256.New()
	h.Write(sessionKeyBytes)
	sessionKey := h.Sum(nil)
	logger.Println("Created session key:", sessionKey)

	// Encrypt ServerReady message
	serverReadyMsg := utils.EncryptAES([]byte("ServerReady"), sessionKey)

	// Send ServerReady message bytes
	conn.Write(serverReadyMsg)

	// Receive ClientReady message from client
	clientReadyBuf := make([]byte, 1024)
	clientReadyLen, err := conn.Read(clientReadyBuf)
	if err != nil {
		logger.Println(err)
		return
	}

	// Decrypt message and establish connection
	decBytes := utils.DecryptAES(clientReadyBuf[:clientReadyLen], sessionKey)
	if string(decBytes) != "ClientReady" {
		logger.Println("Received something other than ClientReady, something is wrong")
		return
	}
	logger.Println("Established encrypted connection")

	for {
		messageBuf := make([]byte, 1024)
		messageLen, err := conn.Read(messageBuf)
		if err != nil {
			logger.Println(err)
			return
		}

		logger.Println("Received encrypted file:", messageBuf[:messageLen])

		decBytes := utils.DecryptAES(messageBuf[:messageLen], sessionKey)
		logger.Println("Decrypted file:", string(decBytes))
	}
}

func StartServer(wg *sync.WaitGroup) {
	logger.Println("Starting server")
	defer wg.Done()

	l, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		logger.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			logger.Println(err)
			return
		}
		handleRequest(c)
	}
}
