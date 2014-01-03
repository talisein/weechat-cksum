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
Use the Makefile, or:

    $ gcc -fPIC -Wall -Wextra -fvisibility=hidden -D_GNU_SOURCE -O3 -c cksum.c
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
A. No. Well, actually, yes! It is more complicated than you might
think. DCC transfers ARE performed over TCP, so the transport of the
file is probably not going to be corrupt. But you can still end up
with a corrupted file:

* The server transfering the file to you may have a corrupted
  copy. This is most evident when both an md5 and a crc32 are
  provided. The md5 will match, indicating that you have the same file
  the server does; but the crc32 will mismatch, indicating that the
  file is not the same as the file's creator intended. I've seen this
  happen more than once.

* The IRC client receiving the file may have a bug. Weechat doesn't
  seem to have such a bug--except when I started hacking on weechat!
  Having this plugin shout about a crc mismatch was extremely helpful
  to catch the bug I introduced on my local branch.

[weechat_link]: http://www.weechat.org/
