#ifndef GLOBAL_HEADER
#define GLOBAL_HEADER

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>

struct section {
	char sh_name[64];
	Elf64_Addr vaddr;
	struct section *next;
};

void check_arguments(int, char**);
struct section * parse_elf_file();
struct section * create_section(char *name, Elf64_Addr addr);

#endif
