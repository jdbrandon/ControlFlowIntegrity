/* include functions for struct sections */

#include "global.h"

struct section * create_section(char *name, Elf64_Addr addr, Elf64_Xword sh_size) {
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
	s->size = sh_size;
	s->next = NULL;
	
	return s;
}

void add_section(section *s, section **list)
{
	if (*list == NULL) {
		*list = s;
		return;
	}
	
	section *ptr = *list;
	while (ptr->next != NULL)
		ptr = ptr->next;
	ptr->next = s;
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

size_t get_section_count(section *list)
{
	size_t count = 0;
	
	section *ptr = list;
	while (ptr != NULL) {
		ptr = ptr->next;
		count++;
	}
	
	return count;
}
