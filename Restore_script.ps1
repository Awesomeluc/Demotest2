# Set the source and destination folders
$backupFile = Read-Host "Enter the path for the backup file"
$destinationFolder = Split-Path -Parent $backupFile

# Check if the backup file exists
if (-not (Test-Path $backupFile)) {
    Write-Host "Error: Backup file does not exist" -ForegroundColor Red
    return
}

# Check if the destination folder exists, if not create it
if (-not (Test-Path $destinationFolder)) {
    try {
        New-Item -ItemType Directory -Path $destinationFolder -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Error creating destination folder: $_" -ForegroundColor Red
        return
    }
}

# Check if the backup file is compressed
if ($backupFile.EndsWith(".zip")) {
    try {
        # Decompress the backup file
        Expand-Archive -Path $backupFile -DestinationPath $destinationFolder -ErrorAction Stop
    } catch {
        Write-Host "Error decompressing backup file: $_" -ForegroundColor Red
        return
    }
    $backupFolder = Join-Path $destinationFolder (Get-ChildItem $destinationFolder | Select-Object -First 1).Name
} else {
    if (-not (Test-Path $backupFile -PathType Container)) {
        Write-Host "Error: Backup file is not a folder" -ForegroundColor Red
        return
    }
    $backupFolder = $backupFile
}

# Loop through the user data folders and copy files and subfolders to the original location
$userDataFolders = @(
    [Environment]::GetFolderPath("MyDocuments")
    [Environment]::GetFolderPath("MyPictures")
    [Environment]::GetFolderPath("MyVideos")
    [Environment]::GetFolderPath("MyMusic")
    Join-Path $env:USERPROFILE "Downloads"
    [Environment]::GetFolderPath("Desktop")
    [Environment]::GetFolderPath("Favorites")
)

foreach ($folder in $userDataFolders) {
    if (Test-Path $folder) {
        $folderName = Split-Path $folder -Leaf
        $sourceFolder = Join-Path $backupFolder $folderName
        if (Test-Path $sourceFolder -PathType Container) {
            Get-ChildItem $sourceFolder -Recurse | ForEach-Object {
                $newPath = Join-Path $folder $_.FullName.Substring($sourceFolder.Length)
                if($_.PsIsContainer) {
                    try {
                        New-Item -ItemType Directory -Path $newPath -Force -ErrorAction Stop | Out-Null
                    } catch {
                        Write-Host "Error creating directory $newPath: $_" -ForegroundColor Red
                        return
                    }
                } else {
                    try {
                        Copy-Item $_.FullName $newPath -Force -ErrorAction Stop
                    } catch {
                        Write-Host "Error copying file $($_.FullName) to $newPath: $_" -ForegroundColor Red
                        return
                    }
                }
            }
            Write-Host "Restored $folderName to $folder"
        } else {
            Write-Host "Warning: $folderName not found in backup folder" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Warning: $folder not found on this system" -ForegroundColor Yellow
    }
}
