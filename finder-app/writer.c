#include<stdio.h>

// tasks from assignment 1
// [ ] Accepts the following arguments: the first argument is a full path to a file (including filename) on the filesystem, referred to below as writefile; the second argument is a text string which will be written within this file, referred to below as writestr
// [ ] Exits with value 1 error and print statements if any of the arguments above were not specified
// [ ] Creates a new file with name and path writefile with content writestr, overwriting any existing file and creating the path if it doesn’t exist. Exits with value 1 and error print statement if the file could not be created.

// addings from assignment 2
// [ ] One difference from the write.sh instructions in Assignment 1:  You do not need to make your "writer" utility create directories which do not exist.  You can assume the directory is created by the caller.
// [ ] Setup syslog logging for your utility using the LOG_USER facility.
// [ ] Use the syslog capability to write a message “Writing <string> to <file>” where <string> is the text string written to file (second argument) and <file> is the file created by the script.  This should be written with LOG_DEBUG level.
// [ ] Use the syslog capability to log any unexpected errors with LOG_ERR level.

int main() {
	printf("Hello World\n");
	return 0;
}
