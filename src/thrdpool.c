#include "thrdpool.h"

#include <pthread.h>
#include <stdlib.h>

typedef struct task_s
{
    void *(*fun)(void*);
    void *arg;
    struct task_s *next;
} task_t;

struct tpool_s
{
    int tnum;
    pthread_t *tids;
    char *tsts;
    pthread_mutex_t lock;
    pthread_cond_t signal;
    task_t *header;
    task_t *last;
    char destroy;
};

static void *__thread_task(void *arg)
{
    tpool_t *tpool = (tpool_t *)arg;
    task_t *task;
    void *(*fun)(void*);
    void *fun_arg;
    char *sts = NULL;
    for(int i = 0; i < tpool->tnum; i++)
    {
        if(tpool->tids[i] == pthread_self())
            sts = &tpool->tsts[i];
    }
    while(1)
    {
        pthread_mutex_lock(&tpool->lock);
        if(tpool->header == NULL && !tpool->destroy)
        {
            *sts = 0;
            pthread_cond_wait(&tpool->signal, &tpool->lock);
        }
        if(tpool->destroy && tpool->header == NULL)
        {
            pthread_mutex_unlock(&tpool->lock);
            pthread_exit(NULL);
        }
        task = tpool->header;
        if(task == NULL)
        {
            pthread_mutex_unlock(&tpool->lock);
            continue;
        }
        *sts = 1;
        tpool->header = task->next;
        fun = task->fun;
        fun_arg = task->arg;
        free(task);
        pthread_mutex_unlock(&tpool->lock);
        fun(fun_arg);
    }
}

static void *__dynamic_thread_task(void *arg)
{
    task_t *task = (task_t *) arg;
    task->fun(task->arg);
    free(task);
    return NULL;
}

tpool_t *tpool_create(__const__ int size)
{
    tpool_t *tpool = (tpool_t *) malloc(sizeof(tpool_t));
    if(pthread_mutex_init(&tpool->lock, NULL) != 0)
    {
        free(tpool);
        return NULL;
    }
    if(pthread_cond_init(&tpool->signal, NULL) != 0)
    {
        free(tpool);
        return NULL;
    }
    tpool->tnum = size;
    tpool->tids = calloc(size, sizeof(pthread_t));
    tpool->tsts = calloc(size, sizeof(char));
    tpool->header = NULL;
    tpool->destroy = 0;
    for(int i = 0; i < size; i++)
    {
        if(pthread_create(&tpool->tids[i], NULL, __thread_task, tpool) != 0)
        {
            free(tpool->tids);
            free(tpool->tsts);
            free(tpool);
            return NULL;
        }
    }
    return tpool;
}

int tpool_add_task(tpool_t *tpool, void *(*fun)(void *), void *arg)
{
    task_t *task = (task_t *) malloc(sizeof(task_t));
    task->fun = fun;
    task->arg = arg;
    task->next = NULL;
    char isbusy = 1;
    pthread_t tid;
    for(int i = 0; i < tpool->tnum; i++)
    {
        if(tpool->tsts[i] == 0)
        {
            isbusy = 0;
            break;
        }
    }
    if(isbusy)
    {
        return pthread_create(&tid, NULL, __dynamic_thread_task, task);
    }
    else
    {
        pthread_mutex_lock(&tpool->lock);
        if(tpool->header == NULL)
        {
            tpool->header = task;
            tpool->last = task;
        }
        else
        {
            tpool->last->next = task;
            tpool->last = task;
        }
        pthread_cond_signal(&tpool->signal);
        pthread_mutex_unlock(&tpool->lock);
    }
    return 0;
}

int tpool_destroy(tpool_t *tpool)
{
    if(tpool->destroy)
        return 1;
    tpool->destroy = 1;
    pthread_mutex_lock(&tpool->lock);
    pthread_cond_broadcast(&tpool->signal);
    pthread_mutex_unlock(&tpool->lock);
    for(int i = 0; i < tpool->tnum; i++)
        pthread_join(tpool->tids[i], NULL);
    pthread_mutex_destroy(&tpool->lock);
    pthread_cond_destroy(&tpool->signal);
    free(tpool->tids);
    free(tpool->tsts);
    free(tpool);
    return 0;
}
