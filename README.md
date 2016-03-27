﻿# Manalyze [![Build Status](https://travis-ci.org/JusticeRage/Manalyze.svg?branch=master)](https://travis-ci.org/JusticeRage/Manalyze) [![Documentation](https://readthedocs.org/projects/manalyze/badge/?version=latest)](https://docs.manalyzer.org/en/latest/)

## Introduction
My work on Manalyze started when my antivirus tried to quarantine my malware sample collection for the thirtieth time. It is also born from my increasing frustration with AV products which make decisions without ever explaining why they deem a file malicious.
Obviously, most people are better off having an antivirus decide what's best for them. But it seemed to me that expert users (i.e. malware analysts) could use a tool which would analyze a PE executable, provide as many data as possible, and leave the final call to them.

If you want to see some sample reports generated by the tool, feel free to try out the web service I created for it: [manalyzer.org](https://manalyzer.org).

## A static analyzer for PE files
Manalyze was written in C++ for Windows and Linux and is released under the terms of the [GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.txt). It is a robust parser for PE files with a flexible plugin architecture which allows users to statically analyze files in-depth. Manalyze...
- Identifies a PE's compiler
- Detects packed executables
- Applies ClamAV signatures
- Searches for suspicious strings
- Looks for malicious import combinations (i.e. `WriteProcessMemory` + `CreateRemoteThread`)
- Detects cryptographic constants (just like IDA's findcrypt plugin)
- Can submit hashes to VirusTotal
- Verifies authenticode signatures (on Windows only)

## How to build
There are few things I hate more than checking out an open-source project and spending two hours trying to build it. This is why I did my best to make Manalyze as easy to build as possible. If these few lines don't work for you, then I have failed at my job and you should drop me a line so I can fix this.

### On Linux and BSD (tested on Debian Jessie and FreeBSD 10.2)
```
$> [sudo or as root] apt-get install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential cmake git
$> [alternatively, also sudo or as root] pkg install boost-libs-1.55.0_8 cmake
$> git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze
$> cmake .
$> make
$> cd bin && ./manalyze --version
```

### On Windows
- Get the Boost libraries from [boost.org](http://boost.org) and install [CMake](http://www.cmake.org/download/).
- Build the boost libraries
  - `cd boost_1_XX_0 && ./bootstrap.bat && ./b2.exe --build-type=complete --with-regex --with-program_options --with-system --with-filesystem`
  - Add an environment variable `BOOST_ROOT` which contains the path to your `boost_1_XX_0` folder.
- Download and install [Git](https://git-scm.com/download/win)
- `git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze && cmake .`
- A Visual Studio project `manalyze.sln` should have appeared in the `Manalyze` folder!

### Offline builds
If you need to build Manalyze on a machine with no internet access, you have to manually check out the following projects:
- [Yara](https://github.com/JusticeRage/yara/archive/master.zip)
- [hash-library](https://github.com/JusticeRage/hash-library/archive/master.zip)

Place the two folders in the `external` folder as `external/yara` and `external/hash-library` respectively. Then run `cmake . -DGitHub=OFF` and continue as you normally would.

### Binaries
[Windows x86 binaries](https://manalyzer.org/static/manalyze.rar)

All the binaries in this archive are signed with a certificate ‎presenting the following fingerprint: `26fc24c12b2d84f77615cf6299e3e4ca4f3878fc`.

## Generating ClamAV rules
Since ClamAV signatures are voluminous and updated regularly, it didn't make a lot of sense to distribute them from GitHub or with the binary. When you try using the ClamAV plugin for the first time, you will likely encounter the following error message: `[!] Error: Could not load yara_rules/clamav.yara`. In order to generate them, simply run the `update_clamav_signatures.py` Python script located in `bin/yara_rules`.

Run the script whenever you want to refresh the signatures.

## Usage

```
$ ./manalyze.exe --help
Usage:
  -h [ --help ]         Displays this message.
  -v [ --version ]      Prints the program's version.
  --pe arg              The PE to analyze. Also accepted as a positional
                        argument. Multiple files may be specified.
  -r [ --recursive ]    Scan all files in a directory (subdirectories will be
                        ignored).
  -o [ --output ] arg   The output format. May be 'raw' (default) or 'json'.
  -d [ --dump ] arg     Dump PE information. Available choices are any
                        combination of: all, summary, dos (dos header), pe (pe
                        header), opt (pe optional header), sections, imports,
                        exports, resources, version, debug, tls
  --hashes              Calculate various hashes of the file (may slow down the
                        analysis!)
  -x [ --extract ] arg  Extract the PE resources to the target directory.
  -p [ --plugins ] arg  Analyze the binary with additional plugins. (may slow
                        down the analysis!)

Available plugins:
  - clamav: Scans the binary with ClamAV virus definitions.
  - compilers: Tries to determine which compiler generated the binary.
  - peid: Returns the PEiD signature of the binary.
  - strings: Looks for suspicious strings (anti-VM, process names...).
  - findcrypt: Detects embedded cryptographic constants.
  - packer: Tries to structurally detect packer presence.
  - imports: Looks for suspicious imports.
  - resources: Analyzes the program's resources.
  - authenticode: Checks if the digital signature of the PE is valid.
  - virustotal: Checks existing AV results on VirusTotal.
  - all: Run all the available plugins.

Examples:
  manalyze.exe program.exe
  manalyze.exe -dresources -dexports -x out/ program.exe
  manalyze.exe --dump=imports,sections --hashes program.exe
  manalyze.exe -r malwares/ --plugins=peid,clamav --dump all
````

## Contact
[![E-Mail](http://manalyzer.org/static/mail.png)](mailto:justicerage *at* manalyzer.org)
[![Tw](http://manalyzer.org/static/twitter.png)](https://twitter.com/JusticeRage)
[![GnuPG](http://manalyzer.org/static/gpg.png)](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x40E9F0A8F5EA8754)
