#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netdb.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

const char *const FILE_NAME = "/var/tmp/aesdsocketdata";

volatile uint8_t g_do_exit = 0;

char *get_ip(struct sockaddr *sa);
static void signal_handler(const int signal_nbr);
void fork_and_exit();
ssize_t forward_line(FILE *const instream, FILE *const outstream);

int main(const int argc, char *argv[])
{
    const int AMOUNT_BACKLOG = 5;
    const int PORT = 9000;
    int retValue;
    // open log
    openlog("aesdsocket", 0, LOG_USER);

    // todo: i. Gracefully exits when SIGINT or SIGTERM is received, completing any open connection operations, closing any open sockets, and deleting the file /var/tmp/aesdsocketdata.
    //           - Logs message to the syslog “Caught signal, exiting” when SIGINT or SIGTERM is received.
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = signal_handler;
    retValue = sigaction(SIGTERM, &new_action, NULL);
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not register for SIGTERM\n");
        return -1;
    }
    retValue = sigaction(SIGINT, &new_action, NULL);
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not register for SIGINT\n");
        return -1;
    }

    int daemonize = 0;
    if (argc > 1 && !strncmp(argv[1], "-d", 2))
    {
        daemonize = 1;
    }

    // todo: b. Opens a stream socket bound to port 9000, failing and returning -1 if any of the socket connection steps fail.
    syslog(LOG_INFO, "Opening socket...\n");
    int socketFD = socket(PF_INET, SOCK_STREAM, 0);
    syslog(LOG_INFO, "Socket opened\n");
    if (socketFD < 0)
    {
        syslog(LOG_ERR, "Could not open socket\n");
        return -1;
    }

    int reuse = 1;
    if (setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0)
    {
        syslog(LOG_ERR, "setsockopt(SO_REUSEADDR) failed\n");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    retValue = bind(socketFD, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not run bind\n");
        return -1;
    }

    /* fork to daemon if requested on commandline */
    if (daemonize)
    {
        closelog();

        fork_and_exit();
        setsid();
        fork_and_exit();

        /* we have to change syslog flags for this */
        openlog("aesdsocket", LOG_PID, LOG_DAEMON);
    }

    // todo: c. Listens for and accepts a connection
    retValue = listen(socketFD, AMOUNT_BACKLOG);
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not run listen\n");
        return -1;
    }
    fprintf(stdout, "Listening on %d\n", PORT);

    // todo: h. Restarts accepting connections from new clients forever in a loop until SIGINT or SIGTERM is received (see below).
    while (g_do_exit == 0)
    {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        memset(&cli_addr, 0, sizeof(cli_addr));

        int connection = accept(socketFD, (struct sockaddr *)&cli_addr, &clilen);
        if (connection < 0)
        {
            syslog(LOG_ERR, "Could not run accept\n");
            continue;
        }
        // todo: d. Logs message to the syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client.
        char *clientIP = get_ip((struct sockaddr *)&cli_addr);
        syslog(LOG_INFO, "Accepted connection from %s\n", clientIP);
        fprintf(stdout, "Accepted connection %s\n", clientIP);
        // todo: e. Receives data over the connection and appends to file /var/tmp/aesdsocketdata, creating this file if it doesn’t exist.
        //           - Your implementation should use a newline to separate data packets received.
        //             In other words a packet is considered complete when a newline character is found in the input receive stream, and each newline should result in an append
        //             to the /var/tmp/aesdsocketdata file.
        //           - You may assume the data stream does not include null characters (therefore can be processed using string handling functions).
        //           - You may assume the length of the packet will be shorter than the available heap size.
        //              In other words, as long as you handle malloc() associated failures with error messages you may discard associated over-length packets.
        FILE *fsock = fdopen(connection, "a+");
        FILE *writeFile = fopen(FILE_NAME, "a");
        ssize_t forwardedBytes = 0;

        setlinebuf(writeFile);
        setlinebuf(fsock);

        forwardedBytes = forward_line(fsock, writeFile);

        if (forwardedBytes == -1)
        {
            syslog(LOG_PERROR, "Error receiving from %s", clientIP);
        }
        else
        {
            syslog(LOG_DEBUG, "Received %ld bytes from %s", forwardedBytes, clientIP);
        }

        // todo: f. Returns the full content of /var/tmp/aesdsocketdata to the client as soon as the received data packet completes.
        //           - You may assume the total size of all packets sent (and therefore size of /var/tmp/aesdsocketdata) will be less than the size of the root filesystem, however you may not assume this total size of all packets sent will be less than the size of the available RAM for the process heap.
        FILE *readFile = freopen(FILE_NAME, "r", writeFile);
        while ((forwardedBytes = forward_line(readFile, fsock)) > 0)
        {
            syslog(LOG_DEBUG, "Sent %ld bytes to %s", forwardedBytes, clientIP);
        }

        fclose(readFile);
        fclose(fsock);

        // todo: g. Logs message to the syslog “Closed connection from XXX” where XXX is the IP address of the connected client.
        syslog(LOG_INFO, "Closed connection from %s", clientIP);

        free(clientIP);
    }

    retValue = remove(FILE_NAME);
    if (retValue != 0)
    {
        syslog(LOG_ERR, "Could not remove file\n");
        return -1;
    }
    syslog(LOG_INFO, "Caught signal, exiting");
    closelog();
    close(socketFD);

    return 0;
}

char *get_ip(struct sockaddr *sa)
{
    char *str;

    switch (sa->sa_family)
    {
    case AF_INET:
    { /* ipv4 */
        struct in_addr ina = ((struct sockaddr_in *)sa)->sin_addr;
        str = calloc(sizeof(char), INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ina, str, INET_ADDRSTRLEN);
        break;
    }
    case AF_INET6:
    { /* ipv6 */
        struct in6_addr in6a = ((struct sockaddr_in6 *)sa)->sin6_addr;
        str = calloc(sizeof(char), INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &in6a, str, INET6_ADDRSTRLEN);
        break;
    }
    default: /* should not happen */
        return "";
    }

    return str;
}

void fork_and_exit()
{
    const int pid = fork();

    if (pid < 0)
    {
        exit(-1);
    }
    else if (pid > 0)
    {
        exit(0);
    }
}

ssize_t forward_line(FILE *const instream, FILE *const outstream)
{
    assert(instream != NULL);
    assert(outstream != NULL);
    char *buffer = NULL;
    size_t buflen = 0;
    ssize_t result;

    result = getline(&buffer, &buflen, instream);

    if (result > 0)
    {
        fputs(buffer, outstream);
        fflush(outstream);
    }

    free(buffer);

    return result;
}

static void signal_handler(const int signal_nbr)
{
    switch (signal_nbr)
    {
    case SIGINT:
    case SIGTERM:
        g_do_exit = 1;
        break;
    default:
        break;
    }
}
