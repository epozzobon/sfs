# SFS python module
Single File System (SFS) is an archive format that simulates a filesystem in a single file. It supports encryption and compression for individual files as well as the entire archive.

It is used, amongst other things, as a file format for the [Cablabel S3 Lite](https://www.cablabel.com/) label printer software.

Information about the format was found at [watto](https://www.watto.org/specs.html?specs=Archive_SFS_AAMVHFSS) and on [hyperspy github](https://github.com/hyperspy/hyperspy/issues/597)

This repository contains an incomplete implementation of SFS with AES-256 and zlib support, specifically used to modify STC files produced by Cablabel S3.
