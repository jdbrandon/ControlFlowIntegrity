/* include functions for struct sections */

#include "global.h"

struct section * create_section(char *name, Elf64_Addr addr) {
	if (strlen(name) > 63) {
		fprintf(stderr, "section name too long.\n");
		exit(1);
	}

	struct section *s = (struct section *)malloc(sizeof(struct section));
	if (s == NULL) {
		fprintf(stderr, "fail to allocate memory in on creating section structure.\n");
		exit(1);
	}
	
	strcpy(s->sh_name, name);
	s->vaddr = addr;
	s->next = NULL;
	
	return s;
}

void free_sections(struct section *s)
{
	struct section *s1;
	
	while (s != NULL) {
		s1 = s;
		s = s->next;
		free(s1);
	}
}
