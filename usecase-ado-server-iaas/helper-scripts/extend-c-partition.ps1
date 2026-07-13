$ErrorActionPreference = 'Stop'
$max = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
$cur = (Get-Partition -DriveLetter C).Size
if ($max -gt $cur + 1GB) {
    Resize-Partition -DriveLetter C -Size $max
    Write-Host ("C: extended to {0} GB" -f [math]::Round($max / 1GB))
} else {
    Write-Host ("C: already spans the OS disk ({0} GB); nothing to extend" -f [math]::Round($cur / 1GB))
}
