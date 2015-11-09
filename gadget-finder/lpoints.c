#include "global.h"

static size_t size = 0x100;

static lpoint * create_lp(uint64_t vaddr)
{
	lpoint *lp = (lpoint *)malloc(sizeof(lpoint));
	if (lp == NULL) {
		fprintf(stderr, "Fail to create an landing-point struct.\n");
		exit(1);
	}
	lp->addr = vaddr;
	lp->next = NULL;
	return lp;
}

static void free_lp_list(lpoint *lp)
{
	lpoint *lp1;
	while (lp != NULL) {
		lp1 = lp;
		lp = lp->next;
		free(lp1);
	}
}

static size_t calc_idx(uint64_t addr)
{
	return (addr * 1103515245 + 12345) & (size - 1);
}

lpoint ** create_lp_array(size_t s)
{
	lpoint ** lpListArray = (lpoint **)malloc(size*8);
	
	if (lpListArray == NULL) {
		fprintf(stderr, "Fail to initialize landing-points array.\n");
		exit(1);
	}
	memset(lpListArray, 0x0, s*8);

	size = s;
	
	return lpListArray;
}

void free_lp_array(lpoint **lpListArray)
{
	for (size_t i=0; i<size; i++) {
		free_lp_list(lpListArray[i]);
	}
}

void add_lp(uint64_t addr, lpoint **lpListArray)
{
	lpoint *lp = create_lp(addr);
		
	if (lpListArray == NULL)
		return;
	
	size_t idx = calc_idx(addr);
	
	if (lpListArray[idx] == NULL) {
		lpListArray[idx] = lp;
		return;
	}
	
	lpoint *ptr = lpListArray[idx];
	if (addr < ptr->addr) {
		lpListArray[idx] = lp;
		lp->next = ptr;
		return;
	}
	
	lpoint *ptr1 = ptr->next;
	while (ptr1 != NULL) {
		if (addr < ptr1->addr)
			break;
		if (addr == ptr1->addr) {
			free(lp);
			return;
		}
			
		ptr = ptr1;
		ptr1 = ptr1->next;
	}
	
	lp->next = ptr1;
	ptr->next = lp;	
}

void delete_lp(uint64_t addr, lpoint **lpListArray)
{
	if (lpListArray == NULL)
		return;
	
	size_t idx = calc_idx(addr);
	
	if (lpListArray[idx] == NULL)
		return;	
	
	lpoint *ptr = lpListArray[idx];
	if (addr == ptr->addr) {
		lpListArray[idx] = ptr->next;
		free(ptr);
		return;
	}
	
	lpoint *ptr1 = ptr->next;
	while (ptr1 != NULL) {
		if (addr < ptr1->addr)
			return;
		if (addr == ptr1->addr) {
			ptr->next = ptr1->next;
			free(ptr1);
		}
		
		ptr = ptr1;
		ptr1 = ptr1->next;
	}
	
	return;
}

int lp_exist(uint64_t addr, lpoint **lpListArray)
{		
	if (lpListArray == NULL) {
		fprintf(stderr, "Not initialze landing-point array first.\n");
		exit(1);
	}
	
	size_t idx = calc_idx(addr);
	lpoint *ptr = lpListArray[idx];

	while (ptr != NULL) {
		if (ptr->addr == addr)
			return 1;
		if (ptr->addr > addr)
			return 0;
		
		ptr = ptr->next;
	}
	
	return 0;
}

void print_lp(lpoint **lpListArray)
{
	if (lpListArray == NULL)
		return;
		
	for (size_t i=0; i<size; i++) {
		lpoint *ptr = lpListArray[i];
		
		while (ptr != NULL) {
			printf("%llx\n", (long long unsigned)ptr->addr);
			ptr = ptr->next;
		}
	}
}

void remove_smallest(lpoint **lpListArray, uint64_t *value)
{
	if (lpListArray == NULL)
		return;
	
	size_t minidx = size;
	uint64_t ret = (uint64_t)-1;
	
	for (size_t i=0; i<size; i++) {
		if (lpListArray[i] != NULL) {
			if (ret > lpListArray[i]->addr) {
				ret = lpListArray[i]->addr;
				minidx = i;
			}
		}
	}
	
	if (minidx == size)
		return;
		
	lpoint *ptr = lpListArray[minidx];	
	lpListArray[minidx] = lpListArray[minidx]->next;
	free(ptr);
	
	*value = ret;
}

int is_empty(lpoint **lpListArray)
{
	if (lpListArray == NULL)
		return 1;
		
	for (size_t i=0; i<size; i++)
		if (lpListArray[i] != NULL)
			return 0;
			
	return 1;
}
