cmd_/home/jx95/pj5src/Rootkit/sneaky_mod.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds --build-id  -o /home/jx95/pj5src/Rootkit/sneaky_mod.ko /home/jx95/pj5src/Rootkit/sneaky_mod.o /home/jx95/pj5src/Rootkit/sneaky_mod.mod.o