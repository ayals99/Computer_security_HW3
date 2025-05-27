#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const int NUMBER_OF_ARGS = 2;

void print_usage(const char* program_name) {
	fprintf(stderr, "Usage: %s filename\n", program_name);
}

int main(int argc, char *argv[]) {
	if (argc != NUMBER_OF_ARGS) {
		print_usage(argv[0]);
		return 1;
	}
	
	char *filename = argv[1];

	printf("Filename: %s\n", filename);

	return 0;
}
