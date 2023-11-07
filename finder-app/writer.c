#include <stdio.h>

#include <syslog.h>

// tasks from assignment 1
// [x] Accepts the following arguments: the first argument is a full path to a file (including filename) on the filesystem,
//     referred to below as writefile; the second argument is a text string which will be written within this file, referred to below as writestr
// [x] Exits with value 1 error and print statements if any of the arguments above were not specified
// [x] Creates a new file with name and path writefile with content writestr, overwriting any existing file and creating the path if it doesn’t exist. Exits with value 1 and error print statement if the file could not be created.

// addings from assignment 2
// [x] One difference from the write.sh instructions in Assignment 1:  You do not need to make your "writer" utility create directories which do not exist.  You can assume the directory is created by the caller.
// [x] Setup syslog logging for your utility using the LOG_USER facility.
// [x] Use the syslog capability to write a message “Writing <string> to <file>” where <string> is the text string written to file (second argument) and <file> is the file created by the script.  This should be written with LOG_DEBUG level.
// [x] Use the syslog capability to log any unexpected errors with LOG_ERR level.

int main(const int argc, char *argv[])
{
    int retValue = -1;
    int programReturnValue = 0;
    // open log
    openlog("writer", 0, LOG_USER);

    // check we only have two arguments
    if (argc != 3)
    {
        syslog(LOG_ERR, "Wrong argument amount\n");
        return 1;
    }

    // parse arguments
    char const *const pWriteFile = argv[1];
    char const *const pWriteString = argv[2];
    syslog(LOG_DEBUG, "Writing %s to %s\n", pWriteString, pWriteFile);

    // create file
    FILE *fp;
    fp = fopen(pWriteFile, "w");
    if (fp == NULL)
    {
        syslog(LOG_ERR, "Could not open the file %s\n", pWriteFile);
        return 1;
    }

    // write to file
    retValue = fprintf(fp, "%s", pWriteString);
    if (retValue < 0)
    {
        syslog(LOG_ERR, "Could not write to file %s\n", pWriteFile);
        programReturnValue = 1;
        // wait for close
    }

    // close file again
    retValue = fclose(fp);
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not close file %s\n", pWriteFile);
        return 1;
    }

    return programReturnValue;
}
