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

* [libjansson](http://www.digip.org/jansson/), for dumping data files in
  JSON format.

* [libmtbl](https://github.com/farsightsec/mtbl), for encoding the underlying
  SSTable files in the MTBL format.

* [libnmsg](https://github.com/farsightsec/nmsg), for importing passive DNS
  data in NMSG format. Additionally, the
  [sie-nmsg](https://github.com/farsightsec/sie-nmsg) message module
  (containing the `SIE/dnsdedupe` message type) is required.

* [libwdns](https://github.com/farsightsec/wdns), for low-level DNS utility
  functions.

`dnstable` relies on `libmtbl` for the actual storage of passive DNS records.
`libmtbl` provides fast lookups of partial keys, so the precise encoding of
dnstable records is optimized to take advantage of this property.
