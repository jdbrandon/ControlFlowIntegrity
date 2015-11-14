/* input handling, commandline argument parsing */

#include "global.h"

extern char infile[], outfile[], outdir[];
extern int save;	//command line switch for saving the output directory
extern unsigned depth;
extern unsigned noshadow;

static int check_ascii_int(char *s)
{
	for (char *c=s; *c!='\0'; c++) {
		if (*c < '0' || *c > '9')
			return 0;	
	}
	
	return 1;
}

/* Usage: %s [options] [arguments] input-file. */
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
				printf("Usage: %s [options] [arguments] input-file.\n", argv[0]);
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
				break;
			case 's':
				save = 1;
				break;
			case 'd':
				i++;
				if (i == argc) {
					fprintf(stderr, "Missing depth parameter.\n");
					exit(1);
				}
				
				if (!check_ascii_int(argv[i])) {
					fprintf(stderr, "Invalid depth parameter.\n");
					exit(1);
				}
				
				depth = atoi(argv[i]);
				if (depth < 2) {
					fprintf(stderr, "Depth has to be greater than 2.\n");
					exit(1);
				}
				break;
			case 'N':
				noshadow = 1;
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

/* 
	create a directory called exesections, which contain files with raw instructions
	from exetuable sections. One file per section. the name is [vaddr]-[section name]
 */
struct section * parse_elf_file()
{
	int error = 0;
	char cmd[32];
	
	//get file size
	struct stat st;
	if(stat(infile, &st)) {
		fprintf(stderr, "Error on getting file stats.\n");
		exit(1);
	}
	
	//open the file
	int infd = open(infile, O_RDONLY);
	if (infd < 0) {
		fprintf(stderr, "Error on opening file: %s.\n", infile);
		exit(1);
	}
	
	//memory-map the file
	void *start = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, infd, 0);
	if (start == MAP_FAILED) {
		fprintf(stderr, "Error on mapping file.\n");
		error = 1;
		goto bad;
	}
	
	//check magic number
	if (*(int *)start != 0x464c457f) {
		fprintf(stderr, "Error elf magic number.\n");
		error = 1;
		goto bad;
	}
	
	Elf64_Ehdr *elfhdr = (Elf64_Ehdr *)start ;
	
	//check file type
	if (elfhdr->e_type != ET_EXEC && elfhdr->e_type != ET_DYN) {
		fprintf(stderr, "File not executable or shared obj.\n");
		error = 2;
		goto bad;
	}
	
	//parse section table
	Elf64_Shdr *shdrs = (Elf64_Shdr *)(start + elfhdr->e_shoff);
	
	//parse string table
	char *strtbl = (char *)(start + shdrs[elfhdr->e_shstrndx].sh_offset);

	if (mkdir(outdir, S_IRWXU)) {
		fprintf(stderr, "fail to create output directory \"exesections\", directory may already exist.\n");
		error = 2;
		goto bad;
	}
	
	//linked list to save the section names and vaddr
	section *list = NULL, *s1;
	
	for (int i=0; i<elfhdr->e_shnum; i++) {
		if (shdrs[i].sh_flags & SHF_EXECINSTR) {
			char name[64];
			if (strlen(&strtbl[shdrs[i].sh_name]) > 32) {
				fprintf(stderr, "Not normal, Section name too long.\n");
				error = 3;
				goto bad;
			}
			
			sprintf(name, "%s/%lx-%s", outdir, shdrs[i].sh_addr, &strtbl[shdrs[i].sh_name]);
			
			//save the file name
			s1 = create_section(name, shdrs[i].sh_addr, shdrs[i].sh_size);
			add_section(s1, &list);

			int fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
			if (fd < 0) {
				fprintf(stderr, "fail to create output file in directory ./exesections.\n");
				error = 3;
				goto bad;
			}
			
			//write to file
			void *sec = (void *)(start + shdrs[i].sh_offset);
			uint64_t secsize = shdrs[i].sh_size;
			if (write(fd, sec, secsize) != secsize) {
				fprintf(stderr, "fail to write to file in directory ./exesections.\n");
				error = 3;
				close(fd);
				goto bad;
			}
			
			close(fd);
		}
	}

	//unmap file
	if (munmap(start, st.st_size)) {
		fprintf(stderr, "fail to unmap file.\n");
		error = 1;
		goto bad;
	}
	
	return list;
	
bad:
	switch (error) {
	case 3:
		sprintf(cmd, "rm -rf %s", outdir);
		system(cmd);
	case 2:
		munmap(start, st.st_size);
	case 1:
		close(infd);
	}
	
	exit(1);
}
