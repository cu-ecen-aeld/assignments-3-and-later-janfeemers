#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...) printf("threading INFO: " msg "\n" , ##__VA_ARGS__)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)


    // wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
void* threadfunc(void* thread_param)
{
    int rc = 0;
    assert(thread_param != NULL);
    DEBUG_LOG("starting threadfunc");
    
    struct thread_data* thread_func_args = (struct thread_data *)thread_param;
    // 1. wait

    DEBUG_LOG("wait before obtaining (%d)", thread_func_args->wait_to_obtain_ms);
    rc = usleep(thread_func_args->wait_to_obtain_ms * 1000);
    if (rc != 0) {
        ERROR_LOG("Attempt to wait_to_obtain_ms failed %d\n", rc);
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }

    DEBUG_LOG("obtaining mutex");    
    rc = pthread_mutex_lock(thread_func_args->mutex);
    if (rc != 0) {
        ERROR_LOG("attempt to obtain mutex failed with %d\n", rc);
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }

    DEBUG_LOG("wait before release (%d)", thread_func_args->wait_to_release_ms);
    rc = usleep(thread_func_args->wait_to_release_ms * 1000);
    if (rc != 0) {
        ERROR_LOG("attempt to wait_to_obtain_ms failed %d\n", rc);
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }

    thread_func_args->thread_complete_success = true;

    DEBUG_LOG("release mutex");    
    rc = pthread_mutex_unlock(thread_func_args->mutex);
    if (rc != 0) {
        ERROR_LOG("attempt to unlock mutex failed with %d\n", rc);
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    int rc = 0;
    struct thread_data * pThreadData = NULL;
    /**
     * allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    pThreadData = (struct thread_data *) malloc(sizeof(struct thread_data));
    if (pThreadData == NULL) {
        ERROR_LOG("attempt to create a new thread_data failed!");
        return false;
    }

    pThreadData->wait_to_obtain_ms = wait_to_obtain_ms;
    pThreadData->wait_to_release_ms = wait_to_release_ms;
    pThreadData->mutex = mutex;

    rc = pthread_create(thread, NULL, threadfunc, (void *) pThreadData);
        if (rc != 0) {
        ERROR_LOG("attempt to create thread failed with %d\n", rc);
        return false;
    }
    return true;
}

