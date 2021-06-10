# Lumina Vac Filter / Module Dumper

This is the code I made from my article on VAC [Quick look around VAC - Part 1 : Module loading](https://whereisr0da.github.io/blog/posts/2021-03-10-quick-vac/)

It can be used as a "VAC Bypass", but bypassing VAC is useless and make your activity more obvious in a sense.

# How to

- Launch `steam.exe` with administrator rights (so `steamservice.dll` is loaded in a single process)
- Inject this code in `steam.exe` process
- Each downloaded and executed VAC module will be dumped in `C:\Lumina\*`
- Each times a VAC module will appear, it will be blocked, but some modules are needed to make games work. So you have to define which modules can be blocked, and add them in the code.

NOTE : Module CRC are different in function of the STEAMID and HWID

# License

- This code is based on already existing resource from zyhp, danielkrupinski and biscoito
- This code is released on MIT License
- This code contain : 
    - [minhook](https://github.com/TsudaKageyu/minhook) : All rights reserved
    - [instr.h](https://github.com/fritzone/obfy) : MIT License
    - [lazy.hpp](https://github.com/JustasMasiulis/lazy_importer) : Apache License
    - [xorstr.hpp](https://github.com/JustasMasiulis/xorstr) : Apache License