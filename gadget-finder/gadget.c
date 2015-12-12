#include "global.h"

gadget * create_gadget(uint64_t start, uint64_t end, void *buf)
{
	gadget * g = (gadget *)malloc(sizeof(gadget));
	if (g == NULL) {
		fprintf(stderr, "Fail to initilize gadget.\n");
		exit(1);
	}
	
	g->start = start;
	g->end = end;
	g->size = end - start;
	g->buf = (unsigned char *)malloc(g->size);
	if (g->buf == NULL) {
		fprintf(stderr, "Fail to initilize gadget instruction buffer.\n");
		exit(1);
	}
	memcpy(g->buf, buf, g->size);
	g->next = NULL;
	return g;
}


void add_gadget(gadget *g, gadget **list)
{
	if (*list == NULL) {
		*list = g;
		return;
	}
	
	gadget *ptr = *list;
	while (ptr->next != NULL)
		ptr = ptr->next;
	
	ptr->next = g;
}

size_t get_gadget_count(gadget *list)
{
	size_t count = 0;
	
	gadget *ptr = list;
	while (ptr != NULL) {
		ptr = ptr->next;
		count++;
	}
	
	return count;
}

void free_gadget(gadget *g)
{
	if (g != NULL) {
		free(g->buf);
		free(g);
	}
}

void free_gadget_list(gadget *list)
{
	while (list != NULL) {
		gadget *ptr = list;
		list = list->next;
		free_gadget(ptr);
	}
}
