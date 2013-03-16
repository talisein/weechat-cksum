weechat-cksum
=============

[Weechat][weechat_link] Plugin that automatically validates MD5/CRC32 checksums

Usage
-----

If you use weechat to download a file and there is a CRC32 tag
anywhere in the filename, when the transfer completes the file will
automatically be hashed and compared versus the expected checksum. A
match or mismatch is reported to the main buffer.

Additionally, if a bot messages you after the xfer and says "Transfer
Completed" and includes an md5sum in the message, that MD5 will also
be verified.

Care is taken to only read the file once, as long as the bot messages
you within 5 seconds of the transfer ending. Otherwise it will be read
twice.

Compiling
---------

    $ gcc -fPIC -Wall -Wextra -fvisibility=hidden -O3 -c cksum.c
    $ gcc -shared -fPIC -fvisibility=hidden -O3 -o cksum.so cksum.o

Installing
----------

Copy cksum.so to your ~/.weechat/plugins/ directory.
You may need to create the directory.

Running
-------

Plugins are automatically started when you start weechat.  But if you
don't want to restart, you can use `/plugin load cksum`

Updating
--------

Be sure to `/plugin unload cksum` before copying over or removing
cksum.so!

Feedback
--------

If you find a bot messaging you a SHA or any other type of checksum,
please let me know. Leave a copy of the bot's complete message that
includes the checksum in a github issue. It is relatively easy to add
a new checksum to check.

FAQ
---

### Q. Why is this a C plugin and not a sensible python/tcl/whatever script?
A. What fun would that be?

### Q. Are you seriously worried about DCC transfers being corrupt?
A. No.

[weechat_link]: http://www.weechat.org/
