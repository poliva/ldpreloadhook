ldpreloadhook
=============

a quick open/close/ioctl/read/write/free symbol hooker

**Usage:**

1. Compile:
<pre>
      $ gcc -fPIC -c -o hook.o hook.c
      $ gcc -shared -o hook.so hook.o -ldl
</pre>

2. preload the library and run the command you want to hook:
<pre>
      LD_PRELOAD="./hook.so" command
</pre>

Optionally, if you want to spy a concrete file you can set the environment variable SPYFILE, for example /dev/serio_raw0:
<pre>
      LD_PRELOAD="./hook.so" SPYFILE="/dev/serio_raw0" command
</pre>

All data read from this file will be saved in /tmp/read_data.bin

All data written to this file will be saved in /tmp/write_data.bin

Optionally, if you want to have a delimiter set in the read/write data files each time the file is opened, you can set the environment variable DELIMITER:
<pre>
      LD_PRELOAD="./hook.so" SPYFILE="/dev/serio_raw0" DELIMITER="---" command
</pre>

You can also spy on free() calls by setting the environment variable SPYFREE, this will print the contents of every buffer before free()ing them:
<pre>
      LD_PRELOAD="./hook.so" SPYFREE=1 command
</pre>
