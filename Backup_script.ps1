# Set the destination folder
$destinationFolder = Read-Host "Enter the path for the backup folder"

# Create a new folder in the destination folder with the current date and time
$backupFolder = Join-Path $destinationFolder (Get-Date -Format "MMddyyyy_HHmmss")
try {
    New-Item -ItemType Directory -Path $backupFolder -ErrorAction Stop
}
catch {
    Write-Host "Error creating backup folder: $($Error[0].Exception.Message)" -ForegroundColor Red
    exit 1
}

# Define an array of user data folders to be backed up
$userDataFolders = @(
    [Environment]::GetFolderPath("MyDocuments")
    [Environment]::GetFolderPath("MyPictures")
    [Environment]::GetFolderPath("MyVideos")
    [Environment]::GetFolderPath("MyMusic")
    Join-Path $env:USERPROFILE "Downloads"
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
# Get the size of the backup folder
$backupFolderSize = (Get-ChildItem $backupFolder -Recurse | Measure-Object -Property Length -Sum).Sum
$backupFolderSizeReadable = "{0:N2}" -f ($backupFolderSize / 1MB)
Write-Host "Backup folder size: $backupFolderSizeReadable MB"

# Calculate estimated compressed size
$backupZipFile = "$backupFolder.zip"
$estimatedZipFileSize = $backupFolderSize * 0.7 # Assumes 30% compression ratio
$estimatedZipFileSizeReadable = "{0:N2}" -f ($estimatedZipFileSize / 1MB)
Write-Host "Estimated compressed size: $estimatedZipFileSizeReadable MB"
# Ask the user if they want to enable compression
$compress = Read-Host "Do you want to compress the backup folder? (Y/N)"
if ($compress -eq "Y") {
    # Compress the backup folder
    $backupZipFile = "$backupFolder.zip"
    Compress-Archive -Path $backupFolder -DestinationPath $backupZipFile
    Write-Host "Backup folder compressed to $backupZipFile"
}







<# Ask the user whether they want to enable compression or not
$enableCompression = Read-Host "Do you want to enable compression? (Y/N)"
if ($enableCompression.ToUpper() -eq "Y") {
    # Compress the backup folder and calculate the compressed file size
    $compressedFile = Join-Path $destinationFolder "$(Split-Path $backupFolder -Leaf).gz"
    try {
        $sourceFiles = Get-ChildItem $backupFolder.FullName -Recurse -File
        $compressedFileSize = 0
     
        # Create a GZipStream object and write the compressed data to the output file
        $stream = New-Object System.IO.FileStream ($compressedFile, 'Create')
        $gzipStream = New-Object System.IO.Compression.GZipStream $stream, ([System.IO.Compression.CompressionMode]::Compress)
        foreach ($sourceFile in $sourceFiles) {
            $sourceStream = $sourceFile.OpenRead()
            $gzipStream.WriteTimeout = 60000 # Timeout in milliseconds
            $gzipStream.Write($sourceStream, $sourceStream.Length)
            $sourceStream.Close()
            $compressedFileSize += $sourceFile.Length
        }
        $gzipStream.Close()
        $stream.Close()

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
        
        $compressedFileSize = [math]::Round($compressedFileSize / 1MB, 2)

        Write-Host "Backup completed successfully. Backup files are located in: $compressedFile"
        Write-Host "Backup folder size: $backupSize $sizeUnit"
        Write-Host "Compressed backup file size: $compressedFileSize MB"
    } catch {
        Write-Host "An error occurred during compression: $($_.Exception.Message)"
    }
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
#>
