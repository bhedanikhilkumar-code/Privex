Add-Type -AssemblyName System.Drawing

function Create-ShieldIcon {
    param(
        [int]$Dimension,
        [string]$Path
    )
    $bmp = New-Object System.Drawing.Bitmap($Dimension, $Dimension)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 9, 13, 22))
    $g.FillEllipse($bgBrush, 0, 0, $Dimension, $Dimension)

    $scale = [double]$Dimension / 192.0
    $pts = @(
        (New-Object System.Drawing.PointF((96.0 * $scale), (24.0 * $scale))),
        (New-Object System.Drawing.PointF((160.0 * $scale), (48.0 * $scale))),
        (New-Object System.Drawing.PointF((160.0 * $scale), (108.0 * $scale))),
        (New-Object System.Drawing.PointF((96.0 * $scale), (168.0 * $scale))),
        (New-Object System.Drawing.PointF((32.0 * $scale), (108.0 * $scale))),
        (New-Object System.Drawing.PointF((32.0 * $scale), (48.0 * $scale)))
    )
    $pt1 = New-Object System.Drawing.PointF(0, 0)
    $pt2 = New-Object System.Drawing.PointF($Dimension, $Dimension)
    $c1 = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)
    $c2 = [System.Drawing.Color]::FromArgb(255, 29, 78, 216)
    $shieldBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($pt1, $pt2, $c1, $c2)
    $g.FillPolygon($shieldBrush, $pts)

    $penWidth = [Math]::Max(2.0, (12.0 * $scale))
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, $penWidth)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPts = @(
        (New-Object System.Drawing.PointF((70.0 * $scale), (94.0 * $scale))),
        (New-Object System.Drawing.PointF((88.0 * $scale), (112.0 * $scale))),
        (New-Object System.Drawing.PointF((126.0 * $scale), (74.0 * $scale)))
    )
    $g.DrawLines($pen, $checkPts)

    $g.Dispose()
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

$destDir = "$PSScriptRoot\..\public\icons"
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
}

Create-ShieldIcon -Dimension 16 -Path "$destDir\icon-16.png"
Create-ShieldIcon -Dimension 32 -Path "$destDir\icon-32.png"
Create-ShieldIcon -Dimension 48 -Path "$destDir\icon-48.png"
Create-ShieldIcon -Dimension 128 -Path "$destDir\icon-128.png"

Get-ChildItem $destDir | Select-Object Name, Length
