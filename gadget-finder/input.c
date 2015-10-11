/* input handling, commandline argument parsing */

#include "global.h"

extern char infile[], outfile[];

void check_arguments(int argc, char *argv[])
{
	outfile[0] = 0x0;
	infile[0] = 0x0;

	for (int i=1; i<argc; i++) {
		//parse commandline options
		if (argv[i][0] == '-') {
			//disallow combining options. don't bother to implement
			if (argv[i][2]) {
				fprintf(stderr, "Invalid option %s.\n", argv[i]);
				exit(1);
			}
			switch (argv[i][1]) {
			case 'h':
				printf("Usage: %s [options] filename.\n", argv[0]);
				exit(0);
			case 'o':
				if (outfile[0]) {
					fprintf(stderr, "Duplicate output file.\n");
					exit(1);
				}
				i = i + 1;
				if (i == argc) {
					fprintf(stderr, "Missing output file name.\n");
					exit(1);
				}
				if (strlen(argv[i]) > 255) {
					fprintf(stderr, "Output file name is too long.\n");
					exit(1);
				}
				strcpy(outfile, argv[i]);
			}
		}
		
		//parse non-option arguments
		else {
			if (infile[0]) {
				fprintf(stderr, "Duplicate input file name.\n");
				exit(1);
			}
			if (strlen(argv[i]) > 255) {
				fprintf(stderr, "Input file name is too long.\n");
				exit(1);
			}
			strcpy(infile, argv[i]);
		}
	}
	
	if (!infile[0]) {
		fprintf(stderr, "Missing input file name.\n");
		exit(1);
	}
}

/* return 32 for x86, 64 for x64, exit directly if file type not supported */
int check_elf_file()
{
    if((input_fd = fopen(infile, "r")) == NULL){
        fprintf(stderr,"Error opening input file: %s\n",infile);
        exit(1);
    }
    
	return 64;
}
