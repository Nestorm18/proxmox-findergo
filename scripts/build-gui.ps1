# build-gui.ps1
# Compila la GUI sin pasar por `wails build` (que en esta versión genera
# un icon.ico corrupto en build/windows/). Generamos el .ico a mano con
# .NET en multi-resolución, lo metemos en un .syso vía rsrc y luego
# compilamos Go con los tags de Wails.

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

Set-Location (Split-Path -Parent $PSScriptRoot)

# 1) Generar icon.ico multi-resolución a partir de icon.ico origen.
Add-Type -AssemblyName System.Drawing
$src = [System.Drawing.Image]::FromFile((Resolve-Path 'icon.ico'))
$sizes = @(16, 32, 48, 64, 128, 256)
$bitmaps = @{}
foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.DrawImage($src, 0, 0, $s, $s)
    $g.Dispose()
    $bitmaps[$s] = $bmp
}
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $ms
$bw.Write([uint16]0)         # reserved
$bw.Write([uint16]1)         # type = icon
$bw.Write([uint16]$sizes.Count)
$headerSize = 6 + 16 * $sizes.Count
$dataOffset = $headerSize
$entries = @()
foreach ($s in $sizes) {
    $imgStream = New-Object System.IO.MemoryStream
    $bitmaps[$s].Save($imgStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $data = $imgStream.ToArray()
    $imgStream.Dispose()
    $entries += [pscustomobject]@{ Size = $s; Data = $data; Offset = $dataOffset }
    $dataOffset += $data.Length
}
foreach ($e in $entries) {
    $w = if ($e.Size -ge 256) { 0 } else { $e.Size }
    $bw.Write([byte]$w)        # width (0 = 256)
    $bw.Write([byte]$w)        # height
    $bw.Write([byte]0)         # color count
    $bw.Write([byte]0)         # reserved
    $bw.Write([uint16]1)       # planes
    $bw.Write([uint16]32)      # bit depth
    $bw.Write([uint32]$e.Data.Length)
    $bw.Write([uint32]$e.Offset)
}
foreach ($e in $entries) { $bw.Write($e.Data) }
$bw.Flush()
$iconPath = Join-Path $PWD 'build\windows\icon.ico'
New-Item -Path (Split-Path $iconPath -Parent) -ItemType Directory -Force | Out-Null
[System.IO.File]::WriteAllBytes($iconPath, $ms.ToArray())
$ms.Dispose()
$bw.Dispose()
foreach ($s in $sizes) { $bitmaps[$s].Dispose() }
$src.Dispose()
Write-Host "icon.ico generado: $iconPath"

# 2) rsrc -> proxmox-findergo-res.syso con icono + manifest
$rsrc = 'C:\Users\Usuario\go\bin\rsrc.exe'
if (-not (Test-Path $rsrc)) {
    throw "rsrc no encontrado en $rsrc. Instala con: go install github.com/akavel/rsrc@latest"
}
$sysoPath = Join-Path $PWD 'proxmox-findergo-res.syso'
& $rsrc -manifest 'proxmox-findergo.exe.manifest' -ico $iconPath -o $sysoPath
if ($LASTEXITCODE -ne 0) { throw "rsrc falló" }
Write-Host "syso generado: $sysoPath"

# 3) go build con los tags de Wails
$out = Join-Path $PWD 'bin\gui\proxmox-findergo.exe'
New-Item -Path (Split-Path $out -Parent) -ItemType Directory -Force | Out-Null
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go build -buildvcs=false -tags 'desktop,wv2runtime.download,production' -ldflags '-w -s -H windowsgui' -o $out .
if ($LASTEXITCODE -ne 0) { throw "go build falló" }
Write-Host "binario: $out"

# 4) Actualizar también main.exe, que es el ejecutable que se suele abrir
#    desde la raíz. Así nunca queda allí una compilación de tipo consola.
$rootOut = Join-Path $PWD 'main.exe'
$legacyBackup = Join-Path $PWD '_archive\main.console.exe.bak'
New-Item -Path (Split-Path $legacyBackup -Parent) -ItemType Directory -Force | Out-Null
if ((Test-Path $rootOut) -and -not (Test-Path $legacyBackup)) {
    Copy-Item -LiteralPath $rootOut -Destination $legacyBackup
}
Copy-Item -LiteralPath $out -Destination $rootOut -Force
Write-Host "acceso directo: $rootOut"

# 5) Limpiar el .syso temporal (el icono real ya está dentro del .exe).
#    Los dejamos en _archive/ por si quieres conservarlos, y los .gitignore
#    se encargan de no trackearlos.
$archiveIcon = Join-Path $PWD '_archive\icon.generated.bak.ico'
$archiveSyso = Join-Path $PWD '_archive\proxmox-findergo-res.syso.bak'
New-Item -Path (Split-Path $archiveIcon -Parent) -ItemType Directory -Force | Out-Null
if (Test-Path $iconPath) { Move-Item $iconPath $archiveIcon -Force }
if (Test-Path $sysoPath) { Move-Item $sysoPath $archiveSyso -Force }
Write-Host "OK"
