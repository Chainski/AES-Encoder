<a href="https://github.com/Chainski/AES-Encoder/blob/main/AES-Encoder.ps1"><img src="https://img.shields.io/badge/power-shell-blue"></a> 
<a href="https://github.com/chainski/AES-Encoder"><img src="https://img.shields.io/badge/OPEN--SOURCE-YES-green"></a>
<a href="https://github.com/chainski/AES-Encoder"><img src="https://img.shields.io/github/stars/chainski/AES-Encoder"></a> 
<a href="https://github.com/chainski/AES-Encoder"><img src="https://img.shields.io/badge/license-GPL--3.0-orange"></a> 
<a href="https://github.com/chainski/AES-Encoder"> <img src="https://img.shields.io/badge/dynamic/json?label=Visitors&query=value&url=https%3A%2F%2Fapi.countapi.xyz%2Fhit%2FChainski%2FAES-Encoder"></a> 

# AES-Encoder 🔒 
![bannner](https://user-images.githubusercontent.com/96607632/197303769-6294023f-4b99-4bf7-a6bb-52dd1a5e6b4f.png)

## PowerShell Crypter 

## Authors

- [Xentropy](http://twitter.com/SamuelAnttila)
- [SecForce](http://twitter.com/SECFORCE_LTD)

[Make your own crypter](https://netsec.expert/2020/02/06/write-a-crypter-in-any-language.html)

## Original Features

- Bypasses All modern AVs in use on VirusTotal 
- Compresses and encrypts powershell scripts
- Has a minimal and often even negative (thanks to the compression) overhead
- Randomizes variable names to further obfuscates the decrypter stub
- Randomizes encryption, compression and even the order that the statements appear in the code for maximum entropy!
- Super easy to modify to create your own crypter variant
- Supports recursive layering (crypter crypting the crypted output)
- Supports Import-Module as well as standard running as long as the input script also supported it
- GPLv3 - Free and Open-Source!
- All features in a single file so you can take it with you anywhere!

## Added Features

- AMSI Bypass
- Unicode Encoding
- HTML Encoding
- URL Encoding

## Usage

```
Import-Module ./AES-Encoder.ps1
Invoke-AES-Encoder -InFile invoke-mimikatz.ps1 -OutFile aesmimi.ps1
```

You will now have an encrypted aesmimi.ps1 file in your current working directory. You can use it in the same way as you would the original script, so in this case:

```
Import-Module ./AES-Encoder.ps1
Invoke-Mimikatz
```
It also supports recursive layering via the -Iterations flag.

```
Invoke-AES-Encoder -InFile invoke-mimikatz.ps1 -OutFile aesmimi.ps1 -Iterations 100
```
**Warning though, the files can get big and generating the output file can take a very long time depending on the scripts and number of iterations requested.**


### DISCLAIMER !!! 

**This tool is for educational use only, the author will not be held responsible for any misuse of this tool.**



#### Support and Contributions
My software is open source and free for public use. 
If you found any of these repos useful and would like to support this project financially, 
feel free to donate to my bitcoin address.

<a href="https://www.blockchain.com/btc/address/16T1fUehoGR4E2sj98u9e9mKuQ7uSLvxRJ"><img src="https://img.shields.io/badge/bitcoin-donate-yellow.svg"></a>
