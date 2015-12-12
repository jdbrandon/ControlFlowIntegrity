#ifndef GLOBAL_HEADER
#define GLOBAL_HEADER

#define CLP_SIG 0xaa401f0f
#define JLP_SIG 0xbb401f0f
#define RLP_SIG 0xcc401f0f
#define PATTERN 0x401f

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <udis86.h>

typedef struct section {
	char sh_name[64];
	Elf64_Addr vaddr;
	Elf64_Xword size;
	struct section *next;
}section;

typedef struct lpoint {
	uint64_t addr;
	struct lpoint *next;
}lpoint;

typedef struct gadget {
	uint64_t start;
	uint64_t end;
	uint64_t size;
	unsigned char *buf;
	struct gadget *next;
}gadget;

void check_arguments(int, char**);
section * parse_elf_file();

section * create_section(char *, Elf64_Addr, Elf64_Xword);
void add_section(section *s, section **list);
void free_sections(struct section *);
size_t get_section_count();

lpoint ** create_lp_array(size_t s);
void free_lp_array(lpoint **lpListArray);
void add_lp(uint64_t addr, lpoint **lpListArray);
void delete_lp(uint64_t addr, lpoint **lpListArray);
void remove_smallest(lpoint **lpListArray, uint64_t *value);
void print_lp(lpoint **lpListArray);
int is_empty(lpoint **lpListArray);

gadget * create_gadget(uint64_t start, uint64_t end, void *buf);
void add_gadget(gadget *g, gadget **list);
size_t get_gadget_count(gadget *list);
void free_gadget(gadget *g);
void free_gadget_list(gadget *list);

void display_gadgets(gadget *list, FILE *fp);

#endif
