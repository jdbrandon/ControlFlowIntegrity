/* handling output formats */

#include "global.h"

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
			fprintf(fp, "\t%llx:", (unsigned long long)addr);
				
			const uint8_t *instbuf = ud_insn_ptr(&ud_obj);
			int inst = *(int *)(instbuf);	
			switch (inst) {
			case CLP_SIG:
				fprintf(fp, "\tclp\t\t<=\n");
				break;
			case JLP_SIG:
				fprintf(fp, "\tjlp\t\t<=\n");
				break;
			case RLP_SIG:
				fprintf(fp, "\trlp\t\t<=\n");
				break;
			default:
				fprintf(fp, "\t%s\n", ud_insn_asm(&ud_obj));			
			}
		}
	
		fprintf(fp, "\n");
	}
}

