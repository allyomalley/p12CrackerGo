# p12CrackerGo

A simple tool to concurrently brute force a password-protected PKCS#12 (PFX/P12) file. This tool accomplishes the same result as my [p12Cracker](https://github.com/allyomalley/p12Cracker) script, but this time written in Go with added concurrency for much faster cracking.
  

![ScreenShot](https://raw.githubusercontent.com/allyomalley/p12CrackerGo/master/image/output.png)

## Installation

Install the tool and required dependencies:

```
go get github.com/allyomalley/p12CrackerGo/...
```

## Usage

*Required arguments:*

* Path to your own wordlist file of password guesses
* Path to the target PKCS12 file
* The number of desired threads for brute forcing (Default: 3)
    

```
go run p12Cracker.go guesses.txt crackme.p12 3
```
