from setuptools import setup, find_packages
import RansomWare

setup(
    name = "RansomWare",
 
    version = RansomWare.__version__,
    packages = find_packages(),
    install_requires = [],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement a RansomWare.",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/RansomWare',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Topic :: Security",
    ],
 
    entry_points = {
        'console_scripts': [
            'RansomWare = RansomWare:cryptolocker'
        ],
    },
    python_requires='>=3.6',
)