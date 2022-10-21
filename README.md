<a href="https://github.com/chainski/AES-Encoder"><img src="https://img.shields.io/badge/OPEN--SOURCE-YES-green"></a>
<a href="https://github.com/chainski/AES-Encoder"><img src="https://img.shields.io/badge/license-GPL--3.0-orange"></a> 


# AES-Encoder
![bannner](https://user-images.githubusercontent.com/96607632/197303769-6294023f-4b99-4bf7-a6bb-52dd1a5e6b4f.png)

## PowerShell Crypter v 1.0

## Authors

- [Xentropy](http://twitter.com/SamuelAnttila)
- [SecForce](http://twitter.com/SECFORCE_LTD)

[Make your own crypter](https://netsec.expert/2020/02/06/write-a-crypter-in-any-language.html)

# Features

## AES-Encoder

- Bypasses AMSI and all modern AVs in use on VirusTotal (as of writing)
- Compresses and encrypts powershell scripts
- Has a minimal and often even negative (thanks to the compression) overhead
- Randomizes variable names to further obfuscate the decrypter stub
- Randomizes encryption, Obfuscate with Unicode and HTML Encoding then Compress for maximum entropy!
- Super easy to modify to create your own crypter variant
- Supports recursive layering (crypter crypting the crypted output)
- Supports Import-Module as well as standard running as long as the input script also supported it
- GPLv3 -- Free and open-source!
- All features in a single file so you can take it with you anywhere!


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



### Support and Contributions
My software is open source and free for public use. 
If you found any of these repos useful and would like to support this project financially, 
feel free to donate to my bitcoin address.

### 16T1fUehoGR4E2sj98u9e9mKuQ7uSLvxRJ
![image](https://user-images.githubusercontent.com/96607632/173610346-a08309b7-7ce5-4be8-88f2-d79cb6e9c3bf.png)
