# SFS python module

This repository contains an incomplete implementation of SFS which I specifically use to generate STC files for the CAB MACH2 300 label printer.

Supported features:
- Encryption of individual files with AES-256
- Zlib compression support
- Replacement of existing files

Known missing features:
- Directories
- Addition and deletion of files
- Encyption of the entire archive

## About Single File System (SFS)

Single File System (SFS) is an archive format that simulates a filesystem in a single file. It supports encryption and compression for individual files as well as the entire archive.

SFS files are recognizable by the first 8 bytes of the file containing the ASCII string AAMVHFSS.

The AES-256 implementation used in SFS files has a bug in the key expansion, which is why this repository implements its own AES key schedule on top of the [python AES implementation by BoppreH](https://github.com/boppreh/aes)

It is used, amongst other things, as a file format for the [Cablabel S3 Lite](https://www.cablabel.com/) label printer software.

Information about the format was found at [watto](https://www.watto.org/specs.html?specs=Archive_SFS_AAMVHFSS) and on [hyperspy github](https://github.com/hyperspy/hyperspy/issues/597)

