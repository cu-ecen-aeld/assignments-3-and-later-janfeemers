#define _GNU_SOURCE // for gettid()
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

// #define DEBUG
// #define DEBUG_PACKET
#define PORT ("9000") // the port users will be connecting to
#define BACKLOG (10)  // how many pending connections queue will hold
#define DATA_PATH "/var/tmp"
#define FILE_NAME "/var/tmp/aesdsocketdata"
#define SOCKET_ERROR (-1)
#define TIMER_PERIOD (10)
#define PACKET_BUF_SIZE (1024 + 10)
#define PACKET_BUF_EXPAND (1024)
#define RECV_BUF_SIZE (1024)

struct thread_params
{
    int client_socket;
    char client_address[INET6_ADDRSTRLEN];
    FILE *pData_file;
    bool is_finished;
};

struct thread_entry
{
    pthread_t thread_id;
    bool is_joined;
    struct thread_params *thread_param;
    SLIST_ENTRY(thread_entry)
    entries;
};

int daemonize();
void *connection_thread(void *args);
void *get_in_addr(struct sockaddr *const sa);
void cleanup(const char *pMesg, const char *const s, const int exitcode);
void create_server_socket();
void create_timer(const unsigned int n, FILE *const file);
void exit_on_error(const char *const pMesg, const char *const s);
void handle_signal(const int signal);
void setup_sig_handler();
void timer_thread(const union sigval arg);

int g_server_socket = -1;
pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;
timer_t g_timer_id;
SLIST_HEAD(thread_list, thread_entry)
g_threads;

int main(int argc, char *argv[])
{
    int opt;
    bool daemonize_flag = false;

    openlog("aesdsocket", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Starting");
    SLIST_INIT(&g_threads);

    // Check if deamon flag specified
    while ((opt = getopt(argc, argv, "d")) != -1)
    {
        switch (opt)
        {
        case 'd':
        {
            daemonize_flag = true;
            break;
        }
        default:
        {
            fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
            exit_on_error("Invalid parameter supplied", NULL);
        }
        }
    }

    // Check presence of /vat/tmp and creates it if not exists
    if (mkdir(DATA_PATH, 0777) && errno != EEXIST)
    {
        exit_on_error("Cannot create /var/tmp path", strerror(errno));
    }

    // Delete stale data file
    remove(FILE_NAME);

    setup_sig_handler();

    // Create server socket and fork
    create_server_socket();

    if (daemonize_flag && daemonize() == -1)
    {
        exit_on_error("Failed to daemonize", NULL);
    }

    if (listen(g_server_socket, BACKLOG) == -1)
    {
        exit_on_error("Failed to listen:", strerror(errno));
    }

    // Open file for writing
    FILE *const file_name = fopen(FILE_NAME, "w+");
    if (file_name == NULL)
    {
        exit_on_error("Failed to open data file: ", strerror(errno));
    }

    create_timer(TIMER_PERIOD, file_name);
    // main accept() loop
    while (1)
    {
        struct sockaddr_storage their_addr;
        socklen_t sin_size = sizeof their_addr;
        pthread_t thread_id;
        struct thread_entry *curr = NULL;

        int client_socket = accept(g_server_socket, (struct sockaddr *)&their_addr, &sin_size);
        if (client_socket == -1)
        {
            exit_on_error("Failed to accept connection:", strerror(errno));
        }

        // Fill in thread params
        struct thread_params *params = malloc(sizeof(struct thread_params));
        params->client_socket = client_socket;
        params->pData_file = file_name;
        params->is_finished = false;

        // Get IP address of the client
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), params->client_address, sizeof(params->client_address));

        if (pthread_create(&thread_id, NULL, connection_thread, params) < 0)
        {
            exit_on_error("pthread_create", strerror(errno));
        }

        struct thread_entry *new_thread = malloc(sizeof(struct thread_entry));
        new_thread->thread_id = thread_id;
        new_thread->is_joined = false;
        new_thread->thread_param = params;
        SLIST_INSERT_HEAD(&g_threads, new_thread, entries);

        // Join exited g_threads
        SLIST_FOREACH(curr, &g_threads, entries)
        {
            if (!curr->is_joined && curr->thread_param->is_finished)
            {
                if (pthread_join(curr->thread_id, NULL) < 0)
                {
                    syslog(LOG_ERR, "pthread_join failed, ignoring ...");
                }
                curr->is_joined = true;
                free(curr->thread_param);
            }
        }
    }
    assert(false);
    return 0;
}

// Send single packet
size_t send_all(int s, char *const buf, size_t len, int flag)
{
    size_t total = 0;        // how many bytes we've sent
    size_t bytes_left = len; // how many we have left to send
    size_t n;

    if (!buf || len < 0)
    {
        return -1;
    }
    if (len == 0)
    {
        return 0;
    }

    while (total < len)
    {
        n = send(s, buf + total, bytes_left, flag);
        if (n == -1)
            return -1;
        total += n;
        bytes_left -= n;
    }
    return total;
}

// Send entire file contents
void send_file(int client_socket, FILE *file_name)
{
#define SEND_BUF_SIZE 1024
    char send_buf[SEND_BUF_SIZE];
    bool no_more_data = false;
    size_t total_bytes_read = 0;
    size_t total_bytes_sent = 0;
    int cur_pos;

    pthread_mutex_lock(&g_file_mutex);

    // Save file pos ptr
    if (!file_name)
    {
        exit_on_error(" no open file in send file 1:", strerror(errno));
    }

    cur_pos = ftell(file_name);
    fseek(file_name, 0, SEEK_SET);

    memset(send_buf, 0, sizeof(send_buf));
    while (1)
    {
        // read from file
        if (!file_name)
        {
            exit_on_error(" no open file in send file 2:", strerror(errno));
        }

        size_t bytes_read = fread(send_buf, 1, sizeof(send_buf), file_name);
        if (bytes_read < sizeof(send_buf))
        {
            if (ferror(file_name))
            {
                exit_on_error("Failed to read data: ", strerror(errno));
            }
            else if (feof(file_name))
            {
                no_more_data = true;
            }
        }
        if (bytes_read == 0)
        {
            break;
        }
        total_bytes_read += bytes_read;

        // Send
        size_t bytes_sent = send_all(client_socket, send_buf, bytes_read, 0);
        if (bytes_sent == -1)
        {
            exit_on_error("Failed to send data: ", strerror(errno));
        }
        total_bytes_sent += bytes_sent;
        if (bytes_sent < bytes_read)
        {
            syslog(LOG_ERR, "Need to fix the send routine");
            break;
        }
        if (no_more_data)
        {
            break;
        }
    }

    // Restore file pos ptr
    if (!file_name)
    {
        exit_on_error(" no open file in send file 3:", strerror(errno));
    }
    fseek(file_name, cur_pos, SEEK_SET);
    pthread_mutex_unlock(&g_file_mutex);
}

// Recv / send thread loop
void *connection_thread(void *args)
{
    struct thread_params *params = (struct thread_params *)args;
    syslog(LOG_INFO, "Accepted connection from %s", params->client_address);

    int client_socket = params->client_socket;
    FILE *data_file = params->pData_file;

    // Allocate packet buffer if empty

    char *packet_buf;
    size_t packet_buf_allocated = PACKET_BUF_SIZE;
    if (!(packet_buf = malloc(packet_buf_allocated)))
    {
        exit_on_error("Failed to malloc memory:", strerror(errno));
    }
    size_t packet_buf_used = 0;
    memset(packet_buf, 0, packet_buf_allocated);

    char recv_buf[RECV_BUF_SIZE];

    // Read and send packets main loop
    while (true)
    {

        // read packet
        memset(recv_buf, 0, sizeof(recv_buf));
        int n = recv(client_socket, recv_buf, sizeof(recv_buf), 0);
        if (n == -1)
            exit_on_error("Failed to recv data:", strerror(errno));

        if (n == 0)
        {
            break;
        }

        if (n > 0)
        {

            // Resize and copy data to packet buffer
            if (packet_buf_used + n + 1 >= packet_buf_allocated)
            {
                packet_buf_allocated += PACKET_BUF_EXPAND;
                char *new_buffer = (char *)realloc(packet_buf, packet_buf_allocated);
                if (new_buffer == NULL)
                {
                    exit_on_error("Failed to realloc memory:", strerror(errno));
                }
                packet_buf = new_buffer;
            }

            // Buffer still too small
            if (packet_buf_used + n + 1 >= packet_buf_allocated)
            {
                exit_on_error("packet_buf really too small, exiting", NULL);
            }

            // Copy data to packet buffer
            strncat(packet_buf, recv_buf, n);
            packet_buf_used += n;
            // Find if packet complete
            char *newline = strchr(packet_buf, '\n');
            if (newline)
            {
                // Compute packet size
                size_t line_length = newline - packet_buf + 1;
                //	 Write packet to file
                pthread_mutex_lock(&g_file_mutex);

                if (!data_file)
                {
                    exit_on_error(" no open file in connection thread:", strerror(errno));
                }

                size_t written_to_file = fwrite(packet_buf, 1, line_length, data_file);
                fflush(data_file);
                pthread_mutex_unlock(&g_file_mutex);
                if (written_to_file < line_length && ferror(data_file))
                    exit_on_error("Failed to write data: ", strerror(errno));

                // Decrease memory usage
                if (packet_buf_allocated > PACKET_BUF_SIZE)
                {
                    packet_buf_allocated = PACKET_BUF_SIZE;
                    char *new_buffer = (char *)realloc(packet_buf, packet_buf_allocated);
                    if (new_buffer == NULL)
                        exit_on_error("Failed to shrink memory: ", strerror(errno));
                    packet_buf = new_buffer;
                }
                memset(packet_buf, 0, packet_buf_allocated);
                packet_buf_used = 0;
                send_file(client_socket, data_file);
            }
        }
    }

    // Close socket
    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
    params->client_socket = -1;

    // Free packet buffer
    free(packet_buf);

    syslog(LOG_INFO, "Closed connection from %s", params->client_address);
    memset(params->client_address, 0, sizeof(params->client_address));

    // Mark thread comp;
    params->is_finished = true;
    return params;
}

void handle_signal(const int signal)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    cleanup(NULL, NULL, 0);
}

void cleanup(const char *const pMesg, const char *const s, const int exitcode)
{
    static bool exit_in_progress = false;
    if (exit_in_progress)
    {
        syslog(LOG_ERR, "already in  cleanup, ignoring ...");
        return;
    }
    exit_in_progress = true;
    bool data_file = true;

    // Delete timer
    timer_delete(g_timer_id);

    // Join all g_threads to finish
    struct thread_entry *curr;
    SLIST_FOREACH(curr, &g_threads, entries)
    {
        if (!curr->is_joined)
        {
            if (pthread_join(curr->thread_id, NULL) < 0)
            {
                syslog(LOG_ERR, "pthread_join failed, ignoring ...");
            }
            curr->is_joined = true;

            // Close data file
            if (data_file && curr->thread_param->pData_file)
            {
                fclose(curr->thread_param->pData_file);
                data_file = false;
            }
            // packet buffer is closed by the thread itself so no check is made to free it here
            // client_socket is closed by the thread itself so no check is made to close it here
            free(curr->thread_param);
        }
    }

    // Remove elements from list
    while (!SLIST_EMPTY(&g_threads))
    {
        curr = SLIST_FIRST(&g_threads);
        SLIST_REMOVE_HEAD(&g_threads, entries);
        free(curr);
    }

    // Close server socket
    if (g_server_socket != -1)
    {
        shutdown(g_server_socket, SHUT_RDWR);
        close(g_server_socket);
    }

    // Write to syslog
    if (pMesg)
    {
        if (s)
            syslog(LOG_ERR, "%s %s", pMesg, s);
        else
            syslog(LOG_ERR, "%s", pMesg);
    }

    // Just in case
    pthread_mutex_unlock(&g_file_mutex);
    remove(FILE_NAME);
    closelog();
    // Exit with exit code
    exit(exitcode);
}

int daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        exit_on_error("Failed to fork:", strerror(errno));
    }

    // Exit if parent
    if (pid > 0)
    {
        syslog(LOG_INFO, "Parent exiting");
        closelog();
        exit(0);
    }

    // stuff before becoming a daemon
    chdir("/");
    umask(0);
    setsid();
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_RDWR);
    syslog(LOG_INFO, "Running as a daemon");
    return 0;
}

void setup_sig_handler()
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

void timer_thread(const union sigval arg)
{
    char msg[100];
    time_t current_time;
    struct tm *local_time;

    FILE *file = (FILE *)arg.sival_ptr;
    if (!file)
    {
        syslog(LOG_INFO, "no open file in timer thread: %s", strerror(errno));
        return;
    }
    current_time = time(NULL);
    if ((local_time = localtime(&current_time)) == NULL)
    {
        exit_on_error("localtime in timer thread:", strerror(errno));
    }

    if (strftime(msg, sizeof(msg), "timestamp: %F %T\n", local_time) == 0)
    {
        exit_on_error("strftime in timer thread:", strerror(errno));
    }

    pthread_mutex_lock(&g_file_mutex);
    if (!file)
    {
        syslog(LOG_INFO, "no open file in timer thread 2: %s", strerror(errno));
    }
    else
    {
        fputs(msg, file);
    }

    if (!file)
    {
        syslog(LOG_INFO, "no open file in timer thread 3: %s", strerror(errno));
    }
    else
    {
        fflush(file);
    }
    pthread_mutex_unlock(&g_file_mutex);
}

void create_timer(const unsigned int n, FILE *const file)
{
    assert(file != NULL);
    struct itimerspec ts;
    struct sigevent se;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = file;
    se.sigev_notify_function = timer_thread;
    se.sigev_notify_attributes = NULL;

    ts.it_value.tv_sec = n;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = n;
    ts.it_interval.tv_nsec = 0;

    if (timer_create(CLOCK_REALTIME, &se, &g_timer_id) == -1)
    {
        exit_on_error("Create timer", NULL);
    }

    if (timer_settime(g_timer_id, 0, &ts, 0) == -1)
    {
        exit_on_error("Set timer", NULL);
    }
}

void create_server_socket()
{
    struct addrinfo hints, *serv_info, *p;
    int rv;
    int yes = 1;

    // Get IP address
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &serv_info)) != 0)
    {
        exit_on_error("getaddrinfo: ", gai_strerror(rv));
    }

    // loop through all the results and bind to the first we can
    for (p = serv_info; p != NULL; p = p->ai_next)
    {
        if ((g_server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
            continue;
        }

        // Work around ... already in use ... errors
        if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            freeaddrinfo(serv_info); // all done with this structure
            exit_on_error("setsockopt(SO_REUSEADDR) failed:", strerror(errno));
        }
        if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) == -1)
        {
            freeaddrinfo(serv_info); // all done with this structure
            exit_on_error("setsockopt(SO_REUSEPORT) failed:", strerror(errno));
        }
        // Bind
        if (bind(g_server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(g_server_socket);
            syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
            continue;
        }

        break;
    }

    // Exit if no address bound
    freeaddrinfo(serv_info); // all done with this structure
    if (p == NULL)
        exit_on_error("server: failed to bind", NULL);
}

void *get_in_addr(struct sockaddr *const sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in *)sa)->sin_addr);
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void exit_on_error(const char *const pMesg, const char *const s)
{
    cleanup(pMesg, s, SOCKET_ERROR);
}
