# Compile exploit and compress file system
musl-gcc -o exploit -static exploit.c # use musl-gcc instead of gcc for smaller binaries
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../

# Run boot
cd ..
./boot.sh