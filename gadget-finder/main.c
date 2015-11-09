/* The body of our parser */

#include <dirent.h>
#include "global.h"

extern char infile[], outfile[], outdir[];
extern int save;
extern unsigned depth;

static int is_cond_jump(ud_mnemonic_code_t m)
{
	return (m == UD_Ijo ||
		m == UD_Ijno ||
		m == UD_Ijb ||
		m == UD_Ijae ||
		m == UD_Ijz ||
		m == UD_Ijnz ||
		m == UD_Ijbe ||
		m == UD_Ija ||
		m == UD_Ijs ||
		m == UD_Ijns ||
		m == UD_Ijp ||
		m == UD_Ijnp ||
		m == UD_Ijl ||
		m == UD_Ijge ||
		m == UD_Ijle ||
		m == UD_Ijg ||
		m == UD_Ijcxz ||
		m == UD_Ijecxz ||
		m == UD_Ijrcxz);
}

static int is_lp(ud_t *udptr)
{
	const uint8_t *instbuf = ud_insn_ptr(udptr);
	int inst = *(int *)(instbuf);
	
	return (inst == CLP_SIG) || (inst == JLP_SIG) || (inst == RLP_SIG);
}

static int check_dynamic_opr(ud_t *udptr)
{
	//obtain the operand of current instruction
	const ud_operand_t *opr = ud_insn_opr(udptr, 0);	
	if (opr == NULL) {
		fprintf(stderr, "Bad jmp instruction at address %p.\n", (void *)ud_insn_off(udptr));
		exit(1);
	}
	
	//if it is a dynamic operand
	if (opr->type == UD_OP_MEM || opr->type == UD_OP_PTR || opr->type == UD_OP_REG)
		return 1;
		
	return 0;
}

uint64_t find_gadget_end(ud_t *udptr, uint64_t *start, lpoint **lpListArray)
{
/******************definition******************/
	unsigned count = 0;

	typedef struct list {
		uint64_t start;
		unsigned depth;
		struct list *next;
	}list;
	
	void free_list(list *l)
	{
		list *l1;
		while (l != NULL) {
			l1 = l;
			l = l->next;
			free(l1);
		}
	}
	
	list *init_list(uint64_t start, unsigned count)
	{
		list *l = (list *)malloc(sizeof(list));
		if (l == NULL) {
			fprintf(stderr, "Fail to allocate memory for list.\n");
			exit(1);
		}
		
		l->start = start;
		l->depth = count;
		l->next = NULL;
		return l;
	}

/***********************alogrithm***********************/
	list *l = (list *)malloc(sizeof(list));
	l->start = *start;
	l->depth = depth;
	l->next = NULL;
	
	list *l1 = l;	//keep track of the list end

	while (ud_disassemble(udptr)) {
	
		ud_mnemonic_code_t m = ud_insn_mnemonic(udptr);
		
		//if it is an invalid instruction
		if (ud_lookup_mnemonic(m) == NULL)
			goto bad;
		
		//if current instruction is a conditional jump, then abandon this gadget
		if (is_cond_jump(m))
			goto bad;
		
		//if it is a return instruction
		if (m == UD_Iret)
			goto bad;
		
		//if it is an unconditional jump, then need to look at the operand
		if (m == UD_Ijmp) {
			//check if it is a dynamic jump
			if (check_dynamic_opr(udptr))
				goto good;
			
			//if it is a static jump, then most likely it goes to the beginning of loops. Don't follow it for now.
			goto bad;
		}
		
		//if it is a call instruction, then check the operand
		if (m == UD_Icall) {
			//check if it is a dynamic call
			if (check_dynamic_opr(udptr))
				goto good;
			
			//if it is a static call, then just go through it
			goto next;
		}
		
		//otherwise, if it is an LP instruction, save it into a list for a potential next gadget start and delete its address from the lpListArray
		if (is_lp(udptr)) {
			uint64_t lpaddr = ud_insn_off(udptr);
			l1->next = init_list(lpaddr, count);
			l1 = l1->next;
			delete_lp(lpaddr, lpListArray);
		}
						
		//go to the next landing point
next:
		count++;
		if (count == l->depth) {
			list *l2 = l;
			l = l->next;
			free(l2);
			if (l == NULL)
				goto bad;
				
			count = 0;
			*start = l->start;
		}
	}

good:
	free_list(l);
	return ud_insn_off(udptr) + ud_insn_len(udptr);

bad:
	free_list(l);
	return 0;
}

static void collect_landing_points(void *start, section *s, lpoint **lpArrayList)
{
	uint64_t secstart = s->vaddr;
	
	for (uint64_t i=0; i<s->size-3; i++) {
		int inst = *((int *)(start + i));
		if ((inst == CLP_SIG) || (inst == JLP_SIG) || (inst == RLP_SIG))
			add_lp(secstart + i, lpArrayList);
	}
}

static gadget * collect_gadgets(unsigned char *start, section *s, lpoint **lpArrayList, unsigned *count)
{
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);								//set disassemble mode to 64-bit
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);					//set syntax to intel
	
	uint64_t lpaddr, end;
	gadget *list = NULL;

	while (!is_empty(lpArrayList)) {
		remove_smallest(lpArrayList, &lpaddr);
		unsigned offset = lpaddr - s->vaddr;
		ud_set_input_buffer(&ud_obj, start+offset+4, s->size-offset-4);
		ud_set_pc(&ud_obj, lpaddr+4);
		end = find_gadget_end(&ud_obj, &lpaddr, lpArrayList);
		if (end != 0) {
			gadget *g = create_gadget(lpaddr, end, start+offset);
			add_gadget(g, &list);
			*count = *count + 1;
		}
	}
	
	return list;
}

int main(int argc, char *argv[])
{
	char cmd[32];
	
	//check command line arguments
	check_arguments(argc, argv);

	//parse the executable file
	section *s = parse_elf_file();
	
	//loop through all executable-section files
	section *l1 = s;
	unsigned count = 0;
	
	//uint64_t start, end;
	FILE * outfp = stdout;
	if (outfile[0]) {
		if ((outfp = fopen(outfile, "wb+")) == NULL) {
			fprintf(stderr, "Fail to open outputfile %s.\n", outfile);
			exit(1);
		}
	}

	//create one gadget list for each executable section	
	size_t secCount = get_section_count(s);
	gadget **glist = (gadget **)malloc(secCount*8);
	
	for (size_t i=0; i<secCount; i++) {
		fprintf(outfp, "%s: %llx\n", l1->sh_name, (unsigned long long int)(l1->vaddr));
	
		int fd = open(l1->sh_name, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Error on opening file: %s.\n", infile);
			exit(1);
		}
		
		void *start = mmap(0, l1->size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (start == MAP_FAILED) {
			fprintf(stderr, "Error on mapping file :%s.\n", l1->sh_name);
			close(fd);
			exit(1);
		}
		
		//collect landing points
		lpoint **lpArrayList = create_lp_array(0x100);
		collect_landing_points(start, l1, lpArrayList);
		glist[i] = collect_gadgets((unsigned char *)start, l1, lpArrayList, &count);
		
		fprintf(outfp, "**********************************************************\n");
		
		display_gadgets(glist[i], outfp);
		
		//go to the next executable section
		munmap(start, l1->size);
		free_lp_array(lpArrayList);
		l1 = l1->next;	
	}


	printf("\nTotally %u gadgets.\n", count);
	
	//clean up
	for (size_t i=0; i<secCount; i++)
		free_gadget_list(glist[i]);
	free(glist);
	
	free_sections(s);
	if (outfp != stdout)
		fclose(outfp);
	sprintf(cmd, "rm -rf %s", outdir);
	if (!save)
		system(cmd);
	
	return 0;
}

