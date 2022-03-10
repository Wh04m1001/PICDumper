sh=`for i in $(objdump -d picdump.exe |grep "^ " |cut -f2);do echo -n '\x'$i;done`
echo -e $sh > picdump.bin
