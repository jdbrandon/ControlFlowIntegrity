/* The body of our parser */

#include <udis86.h>
#include "global.h"

extern char infile[], outfile[];

int main(int argc, char *argv[])
{
	check_arguments(argc, argv);
	printf("input file: %s\n", infile);
	printf("output file: %s\n", outfile);
    return 0;
}
