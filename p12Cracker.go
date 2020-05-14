package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
)

var crackedPassword string
var crackedPrivateKey string
var attempts int
var threads int
var resultsLock sync.RWMutex

func main() {
	if len(os.Args) < 4 {
		color.Red("\nPlease pass the 3 required arguments: path to your wordlist file, path to the PKCS12 file, and the desired number of threads")
		return
	}
	guessesPath := os.Args[1]
	p12Path := os.Args[2]
	threadsString := os.Args[3]

	if threadsString != "" {
		threads, _ = strconv.Atoi(threadsString)
	} else {
		threads = 3
	}

	targetFile, err := os.Open(guessesPath)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(targetFile)
	scanner.Split(bufio.ScanLines)

	p12Bytes, err := ioutil.ReadFile(p12Path)
	if err != nil {
		panic(err)
	}

	fmt.Println("\nBrute forcing...")
	crack(scanner, p12Bytes, threads)
	if crackedPassword != "" {
		color.Green("Match!")
		fmt.Println("\n" + crackedPrivateKey)
		color.Green("Successfully cracked password after " + strconv.Itoa(attempts) + " attempts!")
		color.Green("Password: " + color.HiGreenString(crackedPassword))
	} else {
		color.Red("\nFailed to crack the password - try again with a new wordlist!")
	}
	targetFile.Close()
}

func guess(p12Bytes []byte, password string) string {
	privateKey, _, err := pkcs12.Decode(p12Bytes, password)
	if err == pkcs12.ErrIncorrectPassword {
		return ""
	}
	if err != nil {
		panic(err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)
	return string(keyPem)
}

func crack(scanner *bufio.Scanner, p12Bytes []byte, threads int) {
	semaphore := make(chan bool, threads)
	lineNo := 0
	for scanner.Scan() {
		lineNo = lineNo + 1
		semaphore <- true

		go func(password string, line int) {
			decryptedKey := guess(p12Bytes, password)
			if decryptedKey != "" {
				resultsLock.Lock()
				attempts = line
				crackedPassword = password
				crackedPrivateKey = decryptedKey
				resultsLock.Unlock()
			}
			<-semaphore
		}(scanner.Text(), lineNo)
	}

	for i := 0; i < cap(semaphore); i++ {
		semaphore <- true
	}
}
