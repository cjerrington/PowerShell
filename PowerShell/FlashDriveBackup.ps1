# Get Flash Drive letter from Volume Label and format to a file path; ex: E:\
$flashdrive = (Get-Volume -FileSystemLabel "cerringt").Driveletter
$flashdrive = $flashdrive + ":\"

# Get Backup Drive letter from Volume Label and format to a file path; ex: D:\
$external = (Get-Volume -FileSystemLabel "External").Driveletter
$external = $external + ":\FlashDrive - Backup\"

# Start xcopy with the following protocols:
#	/D - copies all files and overwrites all files that are newer than the destination
#	/E - copies all subdirectories even if they are empty
#	/C - ignores errors
#	/R - copies read-only files
#	/Y - surpresses prompting to confirm
#	/K - retains the read-only attributes on the destination files if present on the source files

xcopy "$flashdrive" "$external"  /D /E /C /R /Y /K

# Pause to review copied files if needed
Pause
