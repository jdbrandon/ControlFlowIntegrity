/* The body of our parser */

#include <udis86.h>
#include "global.h"

extern char infile[], outfile[];

int main(int argc, char *argv[])
{
    ud_t disassembly_obj;
    FILE* input_fd;
    check_arguments(argc, argv);
    printf("input file: %s\n", infile);
    printf("output file: %s\n", outfile);

    if((input_fd = fopen(infile, "r")) == NULL){
        fprintf(stderr,"Error opening input file: %s\n",infile);
        exit(1);
    }
    
    //Disassemble Input
    ud_init(&disassembly_obj);
    ud_set_input_file(&disassembly_obj, input_fd);
    ud_set_mode(&disassembly_obj, 64);
    ud_set_syntax(&disassembly_obj, UD_SYN_INTEL);

    while(ud_disassemble(&disassembly_obj)){
        printf("\t%s\n", ud_insn_asm(&disassembly_obj));
    }

    //Parse Disassembly

    //Display Gadgets

    fclose(input_fd);
    return 0;
}
