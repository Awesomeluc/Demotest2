# Set the destination folder
$destinationFolder = Read-Host "Enter the path for the backup folder"

# Create a new folder in the destination folder with the current date and time
$backupFolder = Join-Path $destinationFolder (Get-Date -Format "yyyyMMdd_HHmmss")
try {
    New-Item -ItemType Directory -Path $backupFolder -ErrorAction Stop
}
catch {
    Write-Host "Error creating backup folder: $($Error[0].Exception.Message)" -ForegroundColor Red
    exit 1
}

# Define an array of user data folders to be backed up
$userDataFolders = @(
    [Environment]::GetFolderPath("Documents")
    [Environment]::GetFolderPath("Pictures")
    [Environment]::GetFolderPath("Videos")
    [Environment]::GetFolderPath("Music")
    [Environment]::GetFolderPath("Downloads")
    [Environment]::GetFolderPath("Desktop")
    [Environment]::GetFolderPath("Favorites")
)

# Loop through the user data folders and copy files and subfolders to the backup folder
foreach ($folder in $userDataFolders) {
    if (Test-Path $folder) {
        $folderName = Split-Path $folder -Leaf
        $newFolder = Join-Path $backupFolder $folderName
        New-Item -ItemType Directory -Path $newFolder
        Get-ChildItem $folder -Recurse | ForEach-Object {
            $newPath = Join-Path $newFolder $_.FullName.Substring($folder.Length)
            if($_.PsIsContainer) {
                New-Item -ItemType Directory -Path $newPath
            } else {
                Copy-Item $_.FullName $newPath
            }
        }
        Write-Host "Backed up $folderName to $newFolder"
    }
}

# Ask the user whether they want to enable compression or not
$enableCompression = Read-Host "Do you want to enable compression? (Y/N)"
if ($enableCompression.ToUpper() -eq "Y") {
    # Compress the backup folder and calculate the compressed file size
    $compressedFile = Join-Path $destinationFolder "$($backupFolder.Name).zip"
    Compress-Archive -Path $backupFolder.FullName -DestinationPath $compressedFile -Force
    $compressedSize = Get-ChildItem $compressedFile -Force | Select-Object -ExpandProperty Length

    # Convert the sizes to gigabytes or megabytes depending on the size
    $backupSize = $(Get-ChildItem $backupFolder -Recurse | Measure-Object -Property Length -Sum).Sum
    if ($backupSize -ge 1GB) {
        $backupSize = [math]::Round($backupSize / 1GB, 2)
        $sizeUnit = "GB"
    } elseif ($backupSize -ge 1MB) {
        $backupSize = [math]::Round($backupSize / 1MB, 2)
        $sizeUnit = "MB"
    } else {
        $sizeUnit = "bytes"
    }

    $compressedSize = [math]::Round($compressedSize / 1MB, 2)

    Write-Host "Backup completed successfully. Backup files are located in: $compressedFile"
    Write-Host "Backup folder size: $backupSize $sizeUnit"
    Write-Host "Compressed backup file size: $compressedSize MB"
} else {
    # Display the size of the backup folder without compression
    $backupSize = $(Get-ChildItem $backupFolder -Recurse | Measure-Object -Property Length -Sum).Sum
    # Convert the size to gigabytes or megabytes depending on the size
    if ($backupSize -ge 1GB) {
        $backupSize = [math]::Round($backupSize / 1GB, 2)
        $sizeUnit = "GB"
    } elseif ($backupSize -ge 1MB) {
        $backupSize = [math]::Round($backupSize / 1MB, 2)
        $sizeUnit = "MB"
    } else {
        $sizeUnit = "bytes"
    }

    Write-Host "Backup completed successfully. Backup files are located in: $backupFolder"
    Write-Host "Backup folder size: $backupSize $sizeUnit"
}