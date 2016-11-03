
2016-04-01 - RDS Version 2.53

Version 2.53 of the RDS is contained on four CDs.

The RDS is divided into four portions according to the SHA-1 hash value of file contents.

The discs contain the following ranges of SHA-1 hash values:

        CD "A"            0000000000000000000000000000000000000000
                        - 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        CD "B"            4000000000000000000000000000000000000000
                        - 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        CD "C"            8000000000000000000000000000000000000000
                        - BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        CD "D"            C000000000000000000000000000000000000000
                        - FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

The RDS, from RDS 2.20 onward, does not support the categorization used in previous releases.
For example, you cannot use CD "B" for exclusion of known operating system applications,
as was possible previously.

NOTE: the data format has not changed, merely the allocation
       of space across the media.

CD "A"    42,828,193 files,  11,796,437  unique SHA-1 values
CD "B"    43,010,229 files,  11,796,722  unique SHA-1 values
CD "C"    42,763,547 files,  11,799,549  unique SHA-1 values
CD "D"    43,506,769 files,  11,785,684  unique SHA-1 values
          -------------------------------------------------
  TOTAL   172,108,738 files, 47,178,392  unique SHA-1 values


The four files named "NSRLFile.txt" on the four CDs should be
concatenated into one file and used as a whole.  When concatenated,
you will have a hashset with a total of 172,108,738 files.
Due to duplication across the CDs, this can be reduced to
47,178,392 unique SHA-1 values.

If you have questions regarding the use of the NIST National Software
Reference Library Reference Data Set, you will find current contact
information given below and at http://www.nsrl.nist.gov .

Hash values of the files in the NSRL RDS are available on the website
to provide traceability, as the RDS may be freely copied to any media.
The RDS is digitally signed to allow NIST to be able to verify that no
changes have been made to its contents. As long as no modifications to
the contents have been made, a notice that NIST is the originator of
the contents must accompany each copy made. If modifications are made,
references to NIST as the producer must be removed.

            National Institute of Standards and Technology
                          ATTN: NSRL Project
                     100 Bureau Drive, Stop 8970
                   Gaithersburg, MD 20899-8970 USA
  E-mail: nsrl@nist.gov   Phone: 301-975-3262   FAX: 301-948-6213
