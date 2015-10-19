/* The body of our parser */

#define INSTR_SIZE_MAX 40
#define BUF_SIZE 64
#define SMALL_BUF 16

#include <udis86.h>
#include <dirent.h>
#include "global.h"

extern char infile[], outfile[], outdir[];

int main(int argc, char *argv[])
{
    size_t len, count = 1;
    char last_instr_hex[INSTR_SIZE_MAX] = "", output_buffer[BUF_SIZE] = "";
    unsigned matched = 0;
    unsigned char sig;
    unsigned short sig2;
    FILE* input_fd;
    const char* tmp;
    section *s, *s1;
    ud_mnemonic_code_t mnemonic;

    check_arguments(argc, argv);
    s = parse_elf_file();
    s1 = s;

    printf("input file: %s\n", infile);
    printf("output file: %s\n", outfile);
    
    while (s1 != NULL) {
        printf("%s\n", s1->sh_name);
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

        //Add special rules for NSA instrumented instructions
        while((matched = fread(&sig, 1, 1, input_fd)) != 0){
            fread_errcheck(matched, 1, "Reading byte");

            if(sig == (CLP_SIG>>24)){
                matched = fread(&sig2, 2, 1, input_fd);
                fread_errcheck(matched, 1, "Tried to read short");
                if(sig2 != PATTERN){
                    fseek(input_fd, ftell(input_fd)-2, SEEK_SET); //rewind 2    
                    continue;
                }
                matched = fread(&sig, 1, 1, input_fd);
                fread_errcheck(matched, 1, "reading sig");
                switch(sig){
                    case CLP_SHORT_SIG:
                        printf("clp\n");
                        break;
                    case RLP_SHORT_SIG:
                        printf("rlp\n");
                        break;
                    case JLP_SHORT_SIG:
                        printf("jlp\n");
                        break;
                    default:
                        printf("default\n");
                        fseek(input_fd, ftell(input_fd)-3, SEEK_SET); //rewind 3
                        continue;
                }
            } else {
                continue;
            }
            while(ud_disassemble(&disassembly_obj)) {
                tmp = ud_insn_hex(&disassembly_obj);

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
                mnemonic = disassembly_obj.mnemonic;
                if(mnemonic == UD_Icall || isJump(mnemonic) || mnemonic == UD_Iret){
                    break;
                }
            }
            //flush last output	
     		write_output(count, output_buffer);
            
            //Maybe we should add logi to follow static jumps here?
            /* if(isJump(mnemonic)){
                
                }
            */
        }

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

/* fread_errcheck
 Error checking function for fread.
 Parameters:
    matched:
        The number of elements matched
    expected:
        The number of elements expected
    msg:
        Error message to be appended in result of a mismatch (aids in locating source of error)

 Description:
    Checks to see if the number of matched elemts is equal to the
    expected number. If they are not equal this indicates that there
    has been an error, and probably too few bytes were read
    This error does not affect further execution so a message is
    printed to stderr and then execution continues.
*/
void fread_errcheck(unsigned matched, unsigned expected, const char* msg){
    if(matched != expected)
        fprintf(stderr, "Error: fread matched %u items instead of %u: %s\n", matched, expected, msg);
}

/* isJump
 Helper function for determining if a disassembled instruction is a type of jump
 Parameters:
    m: the mnemonic to check
 Description:
    Checks agains all available jump instruction mnemonic values as defined in libudis header files.
    returns 1 if m is a mnemmonic for a jump instruction and 0 if it is not.
*/
int isJump(ud_mnemonic_code_t m){
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
        m == UD_Ijrcxz ||
        m == UD_Ijmp);
}
