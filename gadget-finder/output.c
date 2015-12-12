/* handling output formats */

#include "global.h"

void print_bytes(const uint8_t *buf, unsigned size, FILE *fp)
{
	unsigned i, spacenum;
	
	for (i=0; i<size; i++) {
		fprintf(fp, "%02x ", buf[i]);
	}
	
	if (size <= 10)
		spacenum = 32 - size * 3;
	else 
		spacenum = 47 - size * 3;
	
	for (i=0; i<spacenum; i++) {
		fprintf(fp, " ");
	}
}

void display_gadgets(gadget *list, FILE *fp)
{
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);								//set disassemble mode to 64-bit
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);					//set syntax to intel
	
	for (gadget *g=list; g!=NULL; g=g->next) {
		ud_set_pc(&ud_obj, g->start);
		ud_set_input_buffer(&ud_obj, g->buf, g->size);
		
		while (ud_disassemble(&ud_obj)) {
			uint64_t addr = ud_insn_off(&ud_obj);
			fprintf(fp, "  %llx:\t", (unsigned long long)addr);
			print_bytes(ud_insn_ptr(&ud_obj), ud_insn_len(&ud_obj), fp);
			const uint8_t *instbuf = ud_insn_ptr(&ud_obj);
			int inst = *(int *)(instbuf);	
			switch (inst) {
			case CLP_SIG:
				fprintf(fp, "clp\t\t<=\n");
				break;
			case JLP_SIG:
				fprintf(fp, "jlp\t\t<=\n");
				break;
			case RLP_SIG:
				fprintf(fp, "rlp\t\t<=\n");
				break;
			default:
				fprintf(fp, "%s\n", ud_insn_asm(&ud_obj));			
			}
		}
	
		fprintf(fp, "\n");
	}
}

