#ifndef GLOBAL_HEADER
#define GLOBAL_HEADER

#define CLP_SIG 0x0f1f40aa
#define JLP_SIG 0x0f1f40bb
#define RLP_SIG 0x0f1f40cc
#define CLP_SHORT_SIG (CLP_SIG & 0xff)
#define JLP_SHORT_SIG (JLP_SIG & 0xff)
#define RLP_SHORT_SIG (RLP_SIG & 0xff)
#define PATTERN 0x401f

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <udis86.h>

struct section {
	char sh_name[64];
	Elf64_Addr vaddr;
	struct section *next;
};
typedef struct section section;

void check_arguments(int, char**);
void fread_errcheck(unsigned, unsigned, const char*);
void snprintf_errcheck(size_t, size_t);
void write_output(size_t, char*);
int isJump(ud_mnemonic_code_t johnny_mnemonic);
struct section * parse_elf_file();
struct section * create_section(char *name, Elf64_Addr addr);

#endif
