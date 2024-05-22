```markdown
# MFT Utility Functions

This repository provides a set of utility functions for file management and manipulation. The functions are implemented in Python and cover a wide range of file operations including encryption, compression, checksum calculation, and more.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [EncryptFile](#encryptfile)
  - [DecryptFile](#decryptfile)
  - [CompressFile](#compressfile)
  - [DecompressFile](#decompressfile)
  - [CalculateChecksum](#calculatechecksum)
  - [SplitFile](#splitfile)
  - [MergeFiles](#mergefiles)
  - [UploadFile](#uploadfile)
  - [DownloadFile](#downloadfile)
  - [LogTransfer](#logtransfer)
  - [ValidateFile](#validatefile)
  - [MonitorDirectory](#monitordirectory)
  - [SecureDelete](#securedelete)
  - [CreateTempFile](#createtempfile)
  - [CleanUpTempFiles](#cleanuptempfiles)
  - [TrackTransferProgress](#tracktransferprogress)
  - [SendTransferNotification](#sendtransfernotification)
  - [RegisterNotificationHandler](#registernotificationhandler)
  - [ScheduleFileTransfer](#schedulefiletransfer)
  - [SetTransferRateLimit](#settransferratelimit)
  - [GetTransferRateLimit](#gettransferratelimit)
  - [LockFile](#lockfile)
  - [UnlockFile](#unlockfile)
  - [LogError](#logerror)
  - [NormalizeFilePath](#normalizefilepath)
  - [ResolveConflict](#resolveconflict)
  - [AddFileDependency](#addfiledependency)
  - [RemoveFileDependency](#removefiledependency)
  - [RetrieveFileByContent](#retrievefilebycontent)
  - [SanitizeFileData](#sanitizefiledata)
  - [LoadConfiguration](#loadconfiguration)
  - [SaveConfiguration](#saveconfiguration)
  - [GetCrossPlatformPath](#getcrossplatformpath)
  - [ChangeFileOwner](#changefileowner)
  - [GetFileOwner](#getfileowner)
  - [MultiThreadedUpload](#multithreadedupload)
  - [TransformFile](#transformfile)
  - [GetFileAccessTime](#getfileaccesstime)
  - [SetFileAccessTime](#setfileaccesstime)
  - [RenameFile](#renamefile)
  - [GetFileSize](#getfilesize)
  - [CreateDirectory](#createdirectory)
  - [DeleteDirectory](#deletedirectory)
  - [ListFiles](#listfiles)
  - [ListDirectories](#listdirectories)
  - [ValidateFilePath](#validatefilepath)
  - [GetFileMetadata](#getfilemetadata)
  - [SetFileMetadata](#setfilemetadata)
  - [SaveFileVersion](#savefileversion)
  - [RevertToFileVersion](#revertofileversion)
  - [SyncDirectories](#syncdirectories)
  - [VerifyDataIntegrity](#verifydataintegrity)
  - [ArchiveFiles](#archivefiles)
  - [UnarchiveFile](#unarchivefile)
  - [SetFilePermissions](#setfilepermissions)
  - [GetFilePermissions](#getfilepermissions)
  - [AddCustomProtocolHandler](#addcustomprotocolhandler)
  - [HandleCustomProtocolRequest](#handlecustomprotocolrequest)
  - [ReadFile](#readfile)
  - [WriteFile](#writefile)
  - [AppendToFile](#appendtofile)
  - [CopyDirectory](#copydirectory)
  - [DeleteFile](#deletefile)
  - [ListFilesWithExtension](#listfileswithextension)
  - [MoveFile](#movefile)
  - [CompareFiles](#comparefiles)
  - [GetFileModificationTime](#getfilemodificationtime)
  - [SetFileModificationTime](#setfilemodificationtime)
  - [CalculateFileSize](#calculatefilesize)
  - [CheckFileExists](#checkfileexists)
  - [GetAbsolutePath](#getabsolutepath)
  - [ListSubdirectories](#listsubdirectories)
  - [GetFileExtension](#getfileextension)
  - [ChangeFileExtension](#changefileextension)
  - [ReadFileAsBytes](#readfileasbytes)
  - [WriteFileFromBytes](#writefilefrombytes)
  - [CreateTempDirectory](#createtempdirectory)
  - [MoveDirectory](#movedirectory)
  - [CreateFile](#createfile)
  - [ListAllFiles](#listallfiles)
  - [CalculateDirectorySize](#calculatedirectorysize)
  - [FindFilesByName](#findfilesbyname)
  - [ReplaceStringInFile](#replacestringinfile)
  - [IsEmptyDirectory](#isemptydirectory)
  - [WatchDirectory](#watchdirectory)
  
## Installation

To use these utility functions, simply clone the repository and import the `MFT` class into your Python project.

```sh
git clone <repository-url>
```

## Usage

### EncryptFile

Encrypts a file using AES encryption.

```python
mft = MFT()
mft.encrypt_file('path/to/input/file', 'path/to/output/file', 'encryption_key')
```

### DecryptFile

Decrypts a file using AES encryption.

```python
mft.decrypt_file('path/to/encrypted/file', 'path/to/decrypted/file', 'encryption_key')
```

### CompressFile

Compresses a file using gzip.

```python
mft.compress_file('path/to/input/file', 'path/to/output/file.gz')
```

### DecompressFile

Decompresses a gzip file.

```python
mft.decompress_file('path/to/compressed/file.gz', 'path/to/output/file')
```

### CalculateChecksum

Calculates the SHA-256 checksum of a file.

```python
checksum = mft.calculate_checksum('path/to/file')
print(checksum)
```

### SplitFile

Splits a file into parts of the specified size.

```python
parts = mft.split_file('path/to/large/file', 1024 * 1024)
print(parts)
```

### MergeFiles

Merges multiple file parts into a single file.

```python
mft.merge_files(['part1', 'part2', 'part3'], 'path/to/output/file')
```

### UploadFile

Uploads a file to a remote server.

```python
mft.upload_file('server_address', 'path/to/local/file', 'path/to/remote/destination')
```

### DownloadFile

Downloads a file from a remote server.

```python
mft.download_file('server_address', 'path/to/remote/file', 'path/to/local/destination')
```

### LogTransfer

Logs the file transfer action.

```python
mft.log_transfer('upload', 'example.txt', 'success')
```

### ValidateFile

Checks if a file exists and matches the given checksum.

```python
is_valid = mft.validate_file('path/to/file', 'expected_checksum')
print(is_valid)
```

### MonitorDirectory

Monitors a directory for changes and calls the callback function on each event.

```python
def callback(event):
    print(event)

mft.monitor_directory('path/to/directory', callback)
```

### SecureDelete

Securely deletes a file by overwriting its content.

```python
mft.secure_delete('path/to/file')
```

### CreateTempFile

Creates a temporary file with the given prefix and suffix.

```python
temp_file = mft.create_temp_file('prefix', '.txt')
print(temp_file)
```

### CleanUpTempFiles

Removes all temporary files created during the session.

```python
mft.clean_up_temp_files()
```

### TrackTransferProgress

Tracks the progress of file transfer.

```python
def progress_callback(progress):
    print(f'Progress: {progress}%')

mft.track_transfer_progress('path/to/file', progress_callback)
```

### SendTransferNotification

Sends a transfer notification.

```python
mft.send_transfer_notification('upload', 'example.txt', 'success')
```

### RegisterNotificationHandler

Registers a handler for transfer notifications.

```python
def notification_handler(event):
    print(event)

mft.register_notification_handler(notification_handler)
```

### ScheduleFileTransfer

Schedules a file transfer.

```python
import time
transfer_time = time.time() + 60  # Schedule transfer in 60 seconds
mft.schedule_file_transfer('path/to/local/file', 'path/to/remote/destination', transfer_time)
```

### SetTransferRateLimit

Sets the transfer rate limit.

```python
mft.set_transfer_rate_limit(1024)  # 1 KB per second
```

### GetTransferRateLimit

Gets the current transfer rate limit.

```python
rate_limit = mft.get_transfer_rate_limit()
print(rate_limit)
```

### LockFile

Locks a file.

```python
mft.lock_file('path/to/file')
```

### UnlockFile

Unlocks a file.

```python
mft.unlock_file('path/to/file')
```

### LogError

Logs an error with context information.

```python
try:
    raise ValueError('An example error')
except ValueError as e:
    mft.log_error(e, 'Error occurred while processing file')
```

### NormalizeFilePath

Normalizes a file path.

```python
normalized_path = mft.normalize_file_path('path/to/../file')
print(normalized_path)
```



### ResolveConflict

Resolves a conflict between existing and new files by renaming the new file.

```python
mft.resolve_conflict('path/to/existing/file', 'path/to/new/file')
```

### AddFileDependency

Adds a dependency for a file.

```python
mft.add_file_dependency('path/to/file', 'path/to/dependency')
```

### RemoveFileDependency

Removes a dependency for a file.

```python
mft.remove_file_dependency('path/to/file', 'path/to/dependency')
```

### RetrieveFileByContent

Retrieves a file by its content hash.

```python
file_path = mft.retrieve_file_by_content('content_hash', 'path/to/search/directory')
print(file_path)
```

### SanitizeFileData

Sanitizes the content of a file based on provided rules.

```python
sanitization_rules = [
    {'Search': 'old_string', 'Replace': 'new_string'}
]
mft.sanitize_file_data('path/to/file', sanitization_rules)
```

### LoadConfiguration

Loads configuration from a file.

```python
config = mft.load_configuration('path/to/config/file')
print(config)
```

### SaveConfiguration

Saves configuration to a file.

```python
config = {'key': 'value'}
mft.save_configuration('path/to/config/file', config)
```

### GetCrossPlatformPath

Gets a cross-platform compatible file path.

```python
cross_platform_path = mft.get_cross_platform_path('path\\to\\file')
print(cross_platform_path)
```

### ChangeFileOwner

Changes the owner of a file.

```python
mft.change_file_owner('path/to/file', 'new_owner')
```

### GetFileOwner

Gets the owner of a file.

```python
owner = mft.get_file_owner('path/to/file')
print(owner)
```

### MultiThreadedUpload

Uploads a file to a remote server using multiple threads.

```python
mft.multi_threaded_upload('path/to/file', 'server_address', 4)
```

### TransformFile

Transforms a file using a given transformer function.

```python
def transformer(data):
    return data.upper()

mft.transform_file('path/to/input/file', 'path/to/output/file', transformer)
```

### GetFileAccessTime

Gets the last access time of a file.

```python
access_time = mft.get_file_access_time('path/to/file')
print(access_time)
```

### SetFileAccessTime

Sets the last access time of a file.

```python
mft.set_file_access_time('path/to/file', time.time())
```

### RenameFile

Renames a file.

```python
mft.rename_file('path/to/old/file', 'path/to/new/file')
```

### GetFileSize

Gets the size of a file.

```python
file_size = mft.get_file_size('path/to/file')
print(file_size)
```

### CreateDirectory

Creates a new directory.

```python
mft.create_directory('path/to/new/directory')
```

### DeleteDirectory

Deletes a directory.

```python
mft.delete_directory('path/to/directory')
```

### ListFiles

Lists all files in a directory.

```python
files = mft.list_files('path/to/directory')
print(files)
```

### ListDirectories

Lists all directories in a directory.

```python
directories = mft.list_directories('path/to/directory')
print(directories)
```

### ValidateFilePath

Checks if the file path exists and is accessible.

```python
is_valid = mft.validate_file_path('path/to/file')
print(is_valid)
```

### GetFileMetadata

Retrieves metadata for a file.

```python
metadata = mft.get_file_metadata('path/to/file')
print(metadata)
```

### SetFileMetadata

Sets metadata for a file.

```python
metadata = {
    'size': 1024,
    'permissions': 0o644,
    'mod_time': time.time(),
    'is_dir': False
}
mft.set_file_metadata('path/to/file', metadata)
```

### SaveFileVersion

Saves a version of a file.

```python
version_path = mft.save_file_version('path/to/file')
print(version_path)
```

### RevertToFileVersion

Reverts to a saved version of a file.

```python
mft.revert_to_file_version('path/to/file', 'path/to/version/file')
```

### SyncDirectories

Synchronizes the content of two directories.

```python
mft.sync_directories('path/to/source/directory', 'path/to/target/directory')
```

### VerifyDataIntegrity

Verifies the integrity of a file using the specified hash type.

```python
is_valid = mft.verify_data_integrity('path/to/file', 'sha256', 'expected_hash')
print(is_valid)
```

### ArchiveFiles

Creates a zip archive from a list of files.

```python
mft.archive_files(['path/to/file1', 'path/to/file2'], 'path/to/archive.zip')
```

### UnarchiveFile

Extracts a zip archive to the specified destination.

```python
mft.unarchive_file('path/to/archive.zip', 'path/to/destination')
```

### SetFilePermissions

Sets the permissions for a file.

```python
mft.set_file_permissions('path/to/file', 0o644)
```

### GetFilePermissions

Gets the permissions of a file.

```python
permissions = mft.get_file_permissions('path/to/file')
print(permissions)
```

### AddCustomProtocolHandler

Adds a handler for a custom protocol.

```python
def handler(request):
    return {'status': 'success', 'data': request['data']}

mft.add_custom_protocol_handler('my_protocol', handler)
```

### HandleCustomProtocolRequest

Handles a custom protocol request.

```python
response = mft.handle_custom_protocol_request({'protocol': 'my_protocol', 'data': b'data'})
print(response)
```

### ReadFile

Reads the content of a file.

```python
content = mft.read_file('path/to/file')
print(content)
```

### WriteFile

Writes content to a file.

```python
mft.write_file('path/to/file', 'content')
```

### AppendToFile

Appends content to a file.

```python
mft.append_to_file('path/to/file', 'additional content')
```

### CopyDirectory

Recursively copies a directory.

```python
mft.copy_directory('path/to/source/directory', 'path/to/destination/directory')
```

### DeleteFile

Deletes a file.

```python
mft.delete_file('path/to/file')
```

### ListFilesWithExtension

Lists all files with a specific extension in a directory.

```python
files = mft.list_files_with_extension('path/to/directory', '.txt')
print(files)
```

### MoveFile

Moves a file from src to dst.

```python
mft.move_file('path/to/source/file', 'path/to/destination/file')
```

### CompareFiles

Compares the content of two files.

```python
are_equal = mft.compare_files('path/to/file1', 'path/to/file2')
print(are_equal)
```

### GetFileModificationTime

Returns the last modification time of a file.

```python
mod_time = mft.get_file_modification_time('path/to/file')
print(mod_time)
```

### SetFileModificationTime

Sets the last modification time of a file.

```python
mft.set_file_modification_time('path/to/file', time.time())
```

### CalculateFileSize

Returns the size of a file in bytes.

```python
size = mft.calculate_file_size('path/to/file')
print(size)
```

### CheckFileExists

Checks if a file exists.

```python
exists = mft.check_file_exists('path/to/file')
print(exists)
```

### GetAbsolutePath

Returns the absolute path of a file.

```python
absolute_path = mft.get_absolute_path('path/to/file')
print(absolute_path)
```

### ListSubdirectories

Lists all subdirectories in a directory.

```python
subdirectories = mft.list_subdirectories('path/to/directory')
print(subdirectories)
```

### GetFileExtension

Returns the file extension.

```python
extension = mft.get_file_extension('path/to/file')
print(extension)
```

### ChangeFileExtension

Changes the file extension.

```python
new_path = mft.change_file_extension('path/to/file.txt', '.md')
print(new_path)
```

### ReadFileAsBytes

Reads the content of a file as bytes.

```python
data = mft.read_file_as_bytes('path/to/file')
print(data)
```

### WriteFileFromBytes

Writes bytes to a file.

```python
mft.write_file_from_bytes('path/to/file', b'data')
```

### CreateTempDirectory

Creates a temporary directory.

```python
temp_dir = mft.create_temp_directory('prefix')
print(temp_dir)
```

### MoveDirectory

Moves a directory from src to dst.

```python
mft.move_directory('path/to/source/directory', 'path/to/destination/directory')
```

### CreateFile

Creates a file.

```python
mft.create_file('path/to/file')
```

### ListAllFiles

Lists all files in a directory and its subdirectories.

```python
files = mft.list_all_files('path/to/directory')
print(files)
```

### CalculateDirectorySize

Calculates the total size of a directory.

```python
total_size = mft.calculate_directory_size('path/to/directory')
print(total_size)
```

### FindFilesByName

Finds files with a specific name in a directory and its subdirectories.

```python
files = mft

.find_files_by_name('path/to/directory', 'file_name')
print(files)
```

### ReplaceStringInFile

Replaces all occurrences of oldString with newString in a file.

```python
mft.replace_string_in_file('path/to/file', 'old_string', 'new_string')
```

### IsEmptyDirectory

Checks if a directory is empty.

```python
is_empty = mft.is_empty_directory('path/to/directory')
print(is_empty)
```

### WatchDirectory

Watches a directory for changes.

```python
def event_callback(event):
    print(event)

mft.watch_directory('path/to/directory', event_callback)
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
```
