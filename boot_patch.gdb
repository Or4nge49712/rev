set confirm off
set pagination off
target remote :1234

hbreak *0x400eca50
commands $bpnum
  silent
  set {unsigned int}0x3ffc094c = 0x3ffc4afc
  set {unsigned int}0x3ffc095c = 0x00400000
  set {unsigned int}0x3ffc0960 = 0x001640ef
  set $a10 = 0
  printf "[boot] flash_ret check forced to ESP_OK\n"
  continue
end

break *0x400d53e4
printf "[gdb] breakpoints set: flash-check patch + setup()\n"
continue
