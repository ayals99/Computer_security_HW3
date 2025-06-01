#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <limits.h>
#include <unistd.h>

static const int NUMBER_OF_ARGS = 2;
static const char COPMSEC_EA_NAME[] = "security.compsec";
static const unsigned int MAX_CLASS = 3;

void print_usage(const char* program_name) {
	fprintf(stderr, "Usage: %s filename\n", program_name);
}

int validate_filename(char *filename) {
	if (access(filename, F_OK) != 0) {
		// file doesn't exist
		return -1;
	}
	return 0;
}
  
int main(int argc, char *argv[]) {
	if (argc != NUMBER_OF_ARGS) {
		print_usage(argv[0]);
		return 1;
	}
	
	char *filename = argv[1];
	char file_path [PATH_MAX];
	unsigned int class = MAX_CLASS + 1;
	int res = 0;

	res = access(filename, F_OK);
	if (res)
		return 1;
	
	char *found_path = realpath(filename, file_path);
    if (!found_path) {
        return 1;
    }

	res = getxattr(file_path, COPMSEC_EA_NAME, &class, sizeof(unsigned int));
	if (res != sizeof(unsigned int))
		return 1;

	printf("%u\n", class);
	return 0;
}
