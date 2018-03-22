dnstable: encoding format, library, and utilities for passive DNS data
======================================================================

Introduction
------------

`dnstable` implements an encoding format for passive DNS data. It consists of a
C library, `libdnstable`, and several command line utilities for creating,
querying, and merging dnstable data files.

It stores key-value records in Sorted String Table (SSTable) files and provides
high-level interfaces for querying or iterating over the stored records.
dnstable encodes individual records using a format tailored for efficiently
storing passive DNS data and can quickly perform both "forward" and "inverse"
searches.

dnstable has the following dependencies:

* [libmtbl](https://github.com/farsightsec/mtbl), for encoding the underlying
  SSTable files in the MTBL format.

* [libwdns](https://github.com/farsightsec/wdns), for low-level DNS utility
  functions.

`dnstable` relies on `libmtbl` for the actual storage of passive DNS records.
`libmtbl` provides fast lookups of partial keys, so the precise encoding of
dnstable records is optimized to take advantage of this property.

The `dnstable_convert` utility previously in this repository has been split out into its own repository at [dnstable-convert](https://github.com/dnsdb/dnstable-convert) to reduce the dependencies of `dnstable`.
