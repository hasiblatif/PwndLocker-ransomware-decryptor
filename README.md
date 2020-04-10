## PwndLocker Ransomware Decryptor

This is a decryptor for PwndLocker ransomware v1.0 appeared in Nov 2019. This ransomware encrypts files and renames them with
.key or .pwnd extension. If your files are encrypted with these extensions, and have marker "07 c6 a3 f1 59 41 52 bd" at offset 188 from end of encrypted files, you can use this decryptor to fully recover your files. 

Please see settings.py to change some variables for successful decryption. Explanation is given in the file.


## Usage

Usage: python decrypt.py [options]

Options:
  -h, --help        show this help message and exit
  --file=FILE_NAME  Decrypt single file
  --dir=DIR_NAME    Decrypt all files in a directory
  --recursive       Decrypt files in sub-directories recursively, root
                    directory should be provided with --dir option
  --del             Delete encrypted files after decryption. [Caution : NOT
                    recommended until single file decryption is successfully
                    tested

