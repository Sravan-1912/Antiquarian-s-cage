# Builds the signed release APK on Windows.
#
# React Native's Gradle plugin shells out through cmd.exe, which fails on the apostrophe in "Antiquarian's Cage".
# So the project is mirrored to a plain path and built there; the APK is copied back to mobile\dist\.
# Usage (PowerShell):  .\mobile\build-android.ps1
# Native tools write progress to stderr; PowerShell 5.1 would treat that as fatal. Exit codes are checked explicitly.
$ErrorActionPreference = 'Continue'
$src = $PSScriptRoot
$build = 'D:\DevTools\build\cage-mobile'
$jdk = (Get-ChildItem 'D:\DevTools' -Directory -Filter 'jdk-17*' | Select-Object -First 1).FullName
if (-not $jdk) { throw 'JDK 17 not found under D:\DevTools' }

$env:JAVA_HOME = $jdk
$env:ANDROID_HOME = 'D:\DevTools\android-sdk'
$env:GRADLE_USER_HOME = 'D:\DevTools\gradle-home'
$env:npm_config_cache = 'D:\DevTools\npm-cache'
$env:NODE_ENV = 'production'
$env:JAVA_TOOL_OPTIONS = '-Djdk.net.unixdomain.tmpdir=D:\DevTools\tmp -Djava.io.tmpdir=D:\DevTools\tmp'
New-Item -ItemType Directory -Force 'D:\DevTools\tmp', $build | Out-Null

# Mirror sources (not dependencies or build output); robocopy exit codes < 8 mean success.
robocopy $src $build /MIR /XD node_modules dist credentials .expo "android\app\build" "android\build" "android\.gradle" "android\app\.cxx" /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

Push-Location $build
try {
    npm ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    "sdk.dir=D\:\\DevTools\\android-sdk" | Set-Content -Encoding ascii android\local.properties
    # The release key stays in the source tree (gitignored); point Gradle at it explicitly.
    $props = Join-Path $src 'credentials\signing.properties'
    if (-not (Test-Path $props)) { throw "Missing $props (release signing key) - see mobile\README.md" }
    Get-Content $props | ForEach-Object { if ($_ -match '^(CAGE_[A-Z_]+)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2] } }
    Push-Location android
    .\gradlew.bat assembleRelease --no-daemon
    if ($LASTEXITCODE -ne 0) { throw 'Gradle build failed' }
    Pop-Location
    $dist = Join-Path $src 'dist'
    New-Item -ItemType Directory -Force $dist | Out-Null
    $apk = Join-Path $build 'android\app\build\outputs\apk\release\app-release.apk'
    $version = (Get-Content (Join-Path $src 'app.json') -Raw | ConvertFrom-Json).expo.version
    $out = Join-Path $dist "cage-authenticator-$version.apk"
    Copy-Item $apk $out -Force
    $hash = (Get-FileHash $out -Algorithm SHA256).Hash
    "$hash  cage-authenticator-$version.apk" | Set-Content -Encoding ascii (Join-Path $dist 'SHA256SUMS.txt')
    Write-Output "APK: $out"
    Write-Output "SHA-256: $hash"
} finally {
    Pop-Location
}
