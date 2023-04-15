# Set the backup file location
$backupFile = Read-Host "Enter the path for the backup file"

# Set the destination folder as the parent folder of the backup file
$destinationFolder = Split-Path $backupFile -Parent

# Check if the backup file is compressed
if ($backupFile.EndsWith(".zip")) {
    # Decompress the backup file
    Expand-Archive -Path $backupFile -DestinationPath $destinationFolder
    $backupFolder = Join-Path $destinationFolder (Get-ChildItem $destinationFolder | Select-Object -First 1).Name
} else {
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
        if (Test-Path $sourceFolder) {
            Get-ChildItem $sourceFolder -Recurse | ForEach-Object {
                $newPath = Join-Path $folder $_.FullName.Substring($sourceFolder.Length)
                if($_.PsIsContainer) {
                    New-Item -ItemType Directory -Path $newPath -Force
                } else {
                    Copy-Item $_.FullName $newPath -Force
                }
            }
            Write-Host "Restored $folderName to $folder"
        } else {
            Write-Host "Warning: $folderName not found in backup folder" -ForegroundColor Yellow
        }
    }
}
