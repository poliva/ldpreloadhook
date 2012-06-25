ldpreloadhook
=============

a quick open/close/ioctl/read/write syscall hooker

**Usage:**

1. Edit hook.c and configure "spy_file"
2. Compile:
<pre>
      $ gcc -fPIC -c -o hook.o hook.c
      $ gcc -shared -o hook.so hook.o -ldl
</pre>

3. preload the library and run the command you want to hook:
<pre>
      LD_PRELOAD="./hook.so" command
</pre>