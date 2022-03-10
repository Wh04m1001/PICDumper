make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc main.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o main.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o main.o -o picdump.exe
