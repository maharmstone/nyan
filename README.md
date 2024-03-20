Nyan
----

Nyan is a collection of utilities to create and manipulate Microsoft's CAT and
INF files.

Thanks to Matt Graeber (https://github.com/mattifestation) and Michał
Trojnara (https://github.com/mtrojnar) for their reverse-engineering work, which
made this whole thing a lot easier.

## authenticode

Prints the Authenticode hash of a PE file, in the same manner as `sha1sum` etc.
This is a hash of the whole file except the bits relating to signing, and is the
hash that gets embedded into the INF file.

## makecat

Clone of the Microsoft tool `makecat`, used to create a CAT file from a text
CDF file. See https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecat
for documentation.

## stampinf

Clone of the Microsoft tool `stampinf`, which updates the date and version in
an INF file. See https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/stampinf
for documentation.

## To do
* Windows version
* inf2cat
* cat2cdf
* signtool?
