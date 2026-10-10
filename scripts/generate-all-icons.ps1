
Add-Type -AssemblyName System.Drawing

function Resize-ImagePng {
    param(
        [System.Drawing.Image]$SourceImage,
        [int]$TargetWidth,
        [int]$TargetHeight,
        [string]$TargetPath
    )
    $destBmp = New-Object System.Drawing.Bitmap($TargetWidth, $TargetHeight)
    $destBmp.SetResolution($SourceImage.HorizontalResolution, $SourceImage.VerticalResolution)

    $g = [System.Drawing.Graphics]::FromImage($destBmp)
    $g.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceOver
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    $wrapMode = New-Object System.Drawing.Imaging.ImageAttributes
    $wrapMode.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)

    $srcW = $SourceImage.Width
    $srcH = $SourceImage.Height
    $ratio = [Math]::Min([double]$TargetWidth / $srcW, [double]$TargetHeight / $srcH)
    $drawW = [int]($srcW * $ratio)
    $drawH = [int]($srcH * $ratio)
    $offsetX = [int](($TargetWidth - $drawW) / 2)
    $offsetY = [int](($TargetHeight - $drawH) / 2)

    $drawRect = New-Object System.Drawing.Rectangle($offsetX, $offsetY, $drawW, $drawH)
    $g.DrawImage($SourceImage, $drawRect, 0, 0, $srcW, $srcH, [System.Drawing.GraphicsUnit]::Pixel, $wrapMode)

    $dir = [System.IO.Path]::GetDirectoryName($TargetPath)
    if (-not [System.IO.Directory]::Exists($dir)) {
        [System.IO.Directory]::CreateDirectory($dir) | Out-Null
    }

    $destBmp.Save($TargetPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $destBmp.Dispose()
    Write-Host "Generated: $TargetPath ($TargetWidth x $TargetHeight)"
}

function Save-IcoFromPng {
    param(
        [string]$PngPath,
        [string]$IcoPath
    )
    $pngBytes = [System.IO.File]::ReadAllBytes($PngPath)
    $w = $pngBytes[19]
    $h = $pngBytes[23]
    if ($w -eq 0 -or $w -gt 255) { $w = 0 }
    if ($h -eq 0 -or $h -gt 255) { $h = 0 }

    $ico = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ico)

    $bw.Write([UInt16]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]1)

    $bw.Write([byte]$w)
    $bw.Write([byte]$h)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngBytes.Length)
    $bw.Write([UInt32]22)

    $bw.Write($pngBytes)
    $bw.Flush()

    [System.IO.File]::WriteAllBytes($IcoPath, $ico.ToArray())
    $bw.Dispose()
    $ico.Dispose()
    Write-Host "Generated ICO: $IcoPath"
}

$logoPath = "C:\Users\bheda\Music\Desktop\Privex\privex-logo.png"
$srcImg = [System.Drawing.Image]::FromFile($logoPath)

# Centered square emblem extraction
# Bounding box of the emblem in 1600x1800 is X: 196..1402, Y: 128..1248
$emblemSize = 1280
$emblemSrcX = [int](($srcImg.Width - $emblemSize) / 2) # 160
$emblemSrcY = 80 # covers 80..1360
$emblemRect = New-Object System.Drawing.Rectangle($emblemSrcX, $emblemSrcY, $emblemSize, $emblemSize)
$emblemBmp = New-Object System.Drawing.Bitmap($emblemSize, $emblemSize)
$eg = [System.Drawing.Graphics]::FromImage($emblemBmp)
$eg.Clear([System.Drawing.Color]::Transparent)
$eg.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$eg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$eg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$eg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$eg.DrawImage($srcImg, (New-Object System.Drawing.Rectangle(0, 0, $emblemSize, $emblemSize)), $emblemRect, [System.Drawing.GraphicsUnit]::Pixel)
$eg.Dispose()

# 1. Desktop App Icon
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 256 -TargetHeight 256 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\desktop\icon.png"
if ([System.IO.Directory]::Exists("C:\Users\bheda\Music\Desktop\Privex\apps\desktop\dist")) {
    Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 256 -TargetHeight 256 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\desktop\dist\icon.png"
}

# 2. Browser Extension Icons
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 16 -TargetHeight 16 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\icons\icon-16.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 32 -TargetHeight 32 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\icons\icon-32.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 48 -TargetHeight 48 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\icons\icon-48.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 128 -TargetHeight 128 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\icons\icon-128.png"

if ([System.IO.Directory]::Exists("C:\Users\bheda\Music\Desktop\Privex\apps\extension\dist\icons")) {
    Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 16 -TargetHeight 16 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\dist\icons\icon-16.png"
    Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 32 -TargetHeight 32 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\dist\icons\icon-32.png"
    Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 48 -TargetHeight 48 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\dist\icons\icon-48.png"
    Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 128 -TargetHeight 128 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\dist\icons\icon-128.png"
}

# 3. Web App Icons & Favicon
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 192 -TargetHeight 192 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\icon-192.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 512 -TargetHeight 512 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\icon-512.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 32 -TargetHeight 32 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\favicon.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 32 -TargetHeight 32 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\favicon-32x32.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 16 -TargetHeight 16 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\favicon-16x16.png"
Save-IcoFromPng -PngPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\favicon.png" -IcoPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\favicon.ico"

# 4. Mobile App Icons (Android mipmap density buckets)
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 48 -TargetHeight 48 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-mdpi\ic_launcher.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 72 -TargetHeight 72 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-hdpi\ic_launcher.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 96 -TargetHeight 96 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xhdpi\ic_launcher.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 144 -TargetHeight 144 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xxhdpi\ic_launcher.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 192 -TargetHeight 192 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xxxhdpi\ic_launcher.png"

# Also round icon variants for Android
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 48 -TargetHeight 48 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-mdpi\ic_launcher_round.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 72 -TargetHeight 72 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-hdpi\ic_launcher_round.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 96 -TargetHeight 96 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xhdpi\ic_launcher_round.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 144 -TargetHeight 144 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xxhdpi\ic_launcher_round.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 192 -TargetHeight 192 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\res\mipmap-xxxhdpi\ic_launcher_round.png"

# 5. Full Logo Copies with transparent background for UI displays
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\privex-logo.png", $true)
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\desktop\privex-logo.png", $true)
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\desktop\src\renderer\privex-logo.png", $true)
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\public\privex-logo.png", $true)
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\android\app\src\main\assets\privex-logo.png", $true)
[System.IO.File]::Copy($logoPath, "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\privex-logo.png", $true)

# Emblem-only icon PNGs for UI headers & sidebars
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 64 -TargetHeight 64 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\web\public\privex-icon.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 64 -TargetHeight 64 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\desktop\privex-icon.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 64 -TargetHeight 64 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\mobile\public\privex-icon.png"
Resize-ImagePng -SourceImage $emblemBmp -TargetWidth 64 -TargetHeight 64 -TargetPath "C:\Users\bheda\Music\Desktop\Privex\apps\extension\public\privex-icon.png"

$emblemBmp.Dispose()
$srcImg.Dispose()
Write-Host "All icons generated and placed successfully!"
