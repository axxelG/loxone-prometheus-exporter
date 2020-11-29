$EnvFile = "deploy_env.json"

function ConvertFrom-SecureStringPlain {
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecureString
    )
    return [System.Net.NetworkCredential]::new("", $SecureString).Password
}

function New-EnvFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FileName
    )
    $envObject = @{
        BintrayUser = (Read-Host "Bintray user name" -AsSecureString | ConvertFrom-SecureString);
        BintrayAPIKey = (Read-Host "Bintray API key" -AsSecureString | ConvertFrom-SecureString);
    }
    ConvertTo-Json $envObject | Out-File $FileName
}

function Import-EnvFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FileName
    )
    $deployEnv = [PSCustomObject]@{
        BintrayUser = ""
        BintrayAPIKey = ""
    }
    # Convert JSON string to PowerShell SecureString
    $raw = Get-Content $FileName | ConvertFrom-Json
    $deployEnv.BintrayUser = ConvertTo-SecureString -String $raw.BintrayUser
    $deployEnv.BintrayAPIKey = ConvertTo-SecureString -String $raw.BintrayAPIKey

    return $deployEnv
}

function Get-DeployEnv {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FileName
    )

    if (-not (Test-Path $FileName)) {
        New-EnvFile $FileName -ErrorAction Stop
    }
    return Import-EnvFile -FileName $FileName
}

function Invoke-ExternalCommand {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $cmd,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $params
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $cmd
    $startInfo.Arguments = $params
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardOutput = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $startInfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    return $p.StandardOutput.ReadToEnd(), $p.StandardError.ReadToEnd(), $p.ExitCode

}
function Get-CurrentBranch {
    return &git rev-parse --abbrev-ref HEAD
}

function Get-LastVersionTag {
    $stdout, $stderr, $returnCode = Invoke-ExternalCommand "git.exe" "describe --match v[0-9]* --abbrev=0"
    if ($returnCode -eq 128) {
        throw ("No version tag found: $stderr")
    }
    if ($returnCode -ne 0) {
        throw ("Fetching last version tag failed: $stderr")
    }
    return $stdout.Trim()
}

function Get-LastVersionFromTag {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Tag
    )
    return $Tag.substring(1)
}

function New-FileObject {
    [cmdletBinding()]
    param(
        [string]$repo,
        [string]$tag,
        [string]$version,
        [string]$packageVersion,
        [string]$arch
    )
    return [PSCustomObject]@{
        repo = $repo
        tag = $tag
        version = $version
        packageVersion = $packageVersion
        arch = $arch
    }
}

# "Methods" for FileObject
function Get-SourceFilename{
    param(
        [PSCustomObject]$FileObject
    )
    return "loxone-exporter_$($FileObject.tag)-1_$($FileObject.arch).deb"
}

function Get-TargetFilename{
    param(
        [PSCustomObject]$FileObject
    )
    return "loxone-exporter_$($FileObject.tag)-$($FileObject.packageVersion)_$($FileObject.arch).deb"
}

function Get-URI{
    param(
        [PSCustomObject]$FileObject
    )
    return "https://api.bintray.com/content/axel/"+
                 "$($FileObject.repo)/loxone-exporter/"+
                 "$($FileObject.version)-$($FileObject.packageVersion)/"+
                 "$(Get-TargetFilename($FileObject))"+
                 ";deb_distribution=buster"+
                 ";deb_component=main"+
                 ";deb_architecture=$(ConvertTo-DebianArch($FileObject.arch))"+
                 ";publish=1"
}

function ConvertTo-DebianArch {
    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
        [String]$releaserArch
    )
    switch ($releaserArch) {
        "armv7" { return "armhf" }
        "armv6" { return "armel" }
        Default {$releaserArch}
    }
}


$deployEnv = Get-DeployEnv -FileName $EnvFile
$branch = Get-CurrentBranch
$tag = Get-LastVersionTag
$version = Get-LastVersionFromTag -Tag $tag
$DebPackageVersion = 0

$files = @()
switch ($branch) {
    "master" {
        $debRepo = "loxone-exporter_deb"
        # $proc_goreleaser = Start-Process -FilePath 'goreleaser.exe' -ArgumentList "--rm-dist" -NoNewWindow -Wait -ErrorAction Stop -PassThru
        # Workaround until goreleaser works again on windows
        Write-Host "Run 'cd go/src/github.com/axxelG/loxone-prometheus-exporter/ && ./goreleaser --rm-dist' in WSL to build the packages"
        Read-Host "Press Enter to continue"
        $files += ((New-FileObject -repo $debRepo -tag $tag -version $version -packageVersion $DebPackageVersion -arch "arm64"))
        $files += ((New-FileObject -repo $debRepo -tag $tag -version $version -packageVersion $DebPackageVersion -arch "amd64"))
    }
    "dev" {
        $debRepo = "loxone-exporter_deb_dev"
        # $proc_goreleaser = Start-Process -FilePath 'goreleaser.exe' -ArgumentList "--rm-dist", "--snapshot" -NoNewWindow -Wait -ErrorAction Stop -PassThru
        # Workaround until goreleaser works again on windows
        Write-Host "Run 'cd go/src/github.com/axxelG/loxone-prometheus-exporter/ && ./goreleaser --rm-dist --snapshot' in WSL to build the packages"
        Read-Host "Press Enter to continue"
        $files += ((New-FileObject -repo $debRepo -tag $tag -version $version -packageVersion $DebPackageVersion -arch "arm64"))
        $files += ((New-FileObject -repo $debRepo -tag $tag -version $version -packageVersion $DebPackageVersion -arch "amd64"))
    }
    default {
        Write-Error "Wrong branch: $branch" -ErrorAction Stop
    }
}

$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList (ConvertFrom-SecureStringPlain $deployEnv.BintrayUser), $deployEnv.BintrayAPIKey -ErrorAction Stop
$gpg_key_pw = Read-Host -Prompt 'Password for gpg signing key' -AsSecureString
$headers = @{"X-GPG-PASSPHRASE" = (ConvertFrom-SecureStringPlain $gpg_key_pw)}
foreach ($f in $files) {
    Rename-Item -Path "./dist/$(Get-SourceFilename -FileObject $f)" -NewName (Get-TargetFilename -FileObject $f)
    Write-Host (Get-URI -FileObject $f)
    try {
        Invoke-RestMethod -Uri (Get-URI -FileObject $f) -Method Put -InFile "./dist/$(Get-TargetFilename -FileObject $f)" -Headers $headers -Credential $cred
        # Invoke-RestMethod -Uri (Get-URI -FileObject $f) -Method Put -InFile "./dist/$(Get-TargetFilename -FileObject $f)" -Headers $headers -Credential (Get-Credential -UserName axel)
    }    
    catch [System.Net.WebException] {
        $err = $_
        $response = $err.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($response)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Error ($err.ToString() + " Body: " + $responseBody) -ErrorAction Stop
    }
}
