/* The body of our parser */

#define INSTR_SIZE_MAX 40
#define BUF_SIZE 64
#define SMALL_BUF 16

#include <udis86.h>
#include <dirent.h>
#include "global.h"

extern char infile[], outfile[], outdir[];
void snprintf_errcheck(size_t, size_t);
void write_output(size_t, char*);

int main(int argc, char *argv[])
{
    check_arguments(argc, argv);
    printf("input file: %s\n", infile);
    printf("output file: %s\n", outfile);
    
	struct section *s = parse_elf_file();
	struct section *s1 = s;
	
	while (s1 != NULL) {
		printf("%s\n", s1->sh_name);
		size_t len, count = 1;

		char last_instr_hex[INSTR_SIZE_MAX] = "", output_buffer[BUF_SIZE] = "";
		
		FILE* input_fd;
		if((input_fd = fopen(s1->sh_name, "rb")) == NULL) {
			fprintf(stderr,"Error opening input file: %s\n", s1->sh_name);
			exit(1);
		}
		
		ud_t disassembly_obj;
		ud_init(&disassembly_obj);
		ud_set_input_file(&disassembly_obj, input_fd);
		ud_set_mode(&disassembly_obj, 64);
		ud_set_syntax(&disassembly_obj, UD_SYN_INTEL);
		ud_set_pc(&disassembly_obj, s1->vaddr);	
	
		//TODO: Add special rules for NSA instrumented instructions
		while(ud_disassemble(&disassembly_obj)) {
			const char *tmp = ud_insn_hex(&disassembly_obj);
			
			//This coalesces repeated instructions to make output more compressed / readable
			if(strcmp(last_instr_hex, tmp) == 0) {
		    	count++;
		    	continue;
		    }			

			write_output(count, output_buffer);
			count = 1;

			len = snprintf(output_buffer, BUF_SIZE, "0x%.8lx\t%s%s%s", (long unsigned int) ud_insn_off(&disassembly_obj), ud_insn_asm(&disassembly_obj),"%s","%s");
			snprintf_errcheck(len, BUF_SIZE);

		    //update last_instr for repeated instruction coalescing
			len = strlen(tmp);
			strncpy(last_instr_hex, tmp, len);
			last_instr_hex[len] = 0;
		}
		
		//flush last output	
		write_output(count, output_buffer);
		
		//Parse Disassembly

		//Display Gadgets
		
		fclose(input_fd);
		s1 = s1->next;
		
		printf("*********************************************************\n");
	}

	free(s);
    return 0;
}

/* write_output
 Helper function for producing disassembly output.
 Parameters:
    count:
        The number of times an instruction has occured in succession
    buf:
        A preformatted buffer of output that contains the instruction
        offset and the assembly representation of the instruction. The
        buffer should have two %s format string tags in order for this
        function to work properly

 Description:
    If the count is larger than 1, display that information by appending
    (x <number of occurances>) after the instruction. Otherwise print the
    disassembled instruction as usual. If the buf is the empty string no
    output is printed. 

 Note: 
    SMALL_BUF was calculated based on the string length of UINT_MAX when
    represented in decimal notation.
*/

void write_output(size_t count, char* buf){
    size_t len;
    char tmp[SMALL_BUF];
    if(strcmp(buf,"") == 0)
        return;
    if(count > 1){
        len = snprintf(tmp, SMALL_BUF, " (x %zu)", count);
        snprintf_errcheck(len, SMALL_BUF);
        printf(buf, tmp, "\n");
    }
    else printf(buf, "", "\n");
}

/* snprintf_errcheck
 Error checking function for snprintf.
 Parameters:
    written:
        The number of bytes written to the buffer
    bufsz:
        The size of the buffer in bytes

 Description:
    Checks to see if the number of bytes written is equal to the
    size of the buffer. If they are equal this indicates that the
    data written to the destination buffer has been truncated.
    This error does not affect further execution so a message is
    printed to stderr and then execution continues.
*/
void snprintf_errcheck(size_t written, size_t bufsz){
    if(written == bufsz)
        fprintf(stderr, "\n\nError: following output truncated, output buffer size %zu is too small!\n\n", bufsz);
}
