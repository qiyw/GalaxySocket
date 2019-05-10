#include <stdlib.h>
#include <pthread.h>

#include "sockmnr.h"
#include "log.h"

pthread_mutex_t __manager_mutex;

struct
{
    gs_socket_t *last;
    gs_socket_t *next;
} __manager_hearder;

typedef struct
{
    uv_timer_t t;
    gs_socket_t *s;
    int timeout;
    gs_timeout_f cb;
} __manager_timer_t;

static void __timer_finish_close(uv_handle_t *handle)
{
    free(handle);
}

static void __socket_finish_close(uv_handle_t *handle)
{
    gs_socket_t *s = (gs_socket_t *) handle;
    manager_unreference(s);
}

static void __handle(uv_timer_t *handle)
{
    LOG_DEBUG("__handle start\n");
    gs_socket_t *p = NULL;
    gs_socket_t *n;
    gs_socket_t *s = __manager_hearder.next;
    while(s != NULL)
    {
        if(s->count == 0)
        {
            n = s->next;
            if(p == NULL)
                __manager_hearder.next = n;
            else
                p->next = n;
            if(n == NULL)
                __manager_hearder.last = p;
            free(s);
            s = n;
        }
        else
        {
            p = s;
            s = s->next;
        }
    }

    LOG_DEBUG("__handle end\n");
}

static void __timeout_handle(uv_timer_t *handle)
{
    LOG_DEBUG("__timeout_handle start\n");
    __manager_timer_t *timer = (__manager_timer_t *) handle;
    gs_socket_t *s = timer->s;
    time_t now = time(NULL);
    char flg = 0;
    if((now - s->act_time) > timer->timeout)
    {
        flg = 1;
        manager_close(s);
        if(timer->cb != NULL)
            timer->cb(s);
    }
    if(manager_isclosed(s))
    {
        manager_unreference(s);
        uv_close((uv_handle_t *) timer, __timer_finish_close);
        if(flg == 0)
            if(timer->cb != NULL)
                timer->cb(s);
    }
    LOG_DEBUG("__timeout_handle end\n");
}

void manager_bind_loop(uv_loop_t *loop)
{
    LOG_DEBUG("manager_bind_loop start\n");
    __manager_hearder.last = NULL;
    __manager_hearder.next = NULL;
    pthread_mutex_init(&__manager_mutex, NULL);
    uv_timer_t *timer = (uv_timer_t *) malloc(sizeof(uv_timer_t));
    uv_timer_init(loop, timer);
    uv_timer_start(timer, __handle, 10000, 10000);
    LOG_DEBUG("manager_bind_loop end\n");
}

void manager_register(gs_socket_t *s)
{
    LOG_DEBUG("manager_register start\n");
    pthread_mutex_lock(&__manager_mutex);
    if(__manager_hearder.next == NULL)
        __manager_hearder.next = s;
    else
        __manager_hearder.last->next = s;
    __manager_hearder.last = s;
    pthread_mutex_unlock(&__manager_mutex);
    s->next = NULL;
    s->count = 1;
    s->is_closed = 0;
    LOG_DEBUG("manager_register end\n");
}

void manager_reference(gs_socket_t *s)
{
    s->count++;
}

void manager_unreference(gs_socket_t *s)
{
    s->count--;
}

void manager_close(gs_socket_t *s)
{
    LOG_DEBUG("manager_close start\n");
    if(!s->is_closed)
    {
        s->count--;
        manager_reference(s);
        uv_close((uv_handle_t *) s, __socket_finish_close);
        s->is_closed = 1;
        if(s->len != 0)
        {
            free(s->buf);
        }
    }
    LOG_DEBUG("manager_close end\n");
}

char manager_isclosed(__const__ gs_socket_t *s)
{
    return s->is_closed;
}

void manager_timeout(uv_loop_t *loop, __const__ gs_socket_t *s, int timeout_sec, gs_timeout_f cb)
{
    LOG_DEBUG("manager_timeout start\n");
    __manager_timer_t *timer = (__manager_timer_t *) malloc(sizeof(__manager_timer_t));
    uv_timer_init(loop, (uv_timer_t *) timer);
    timer->s = (gs_socket_t *) s;
    timer->timeout = timeout_sec;
    timer->cb = cb;
    manager_reference(timer->s);
    uv_timer_start((uv_timer_t *) timer, __timeout_handle, 10000, 10000);
    LOG_DEBUG("manager_timeout end\n");
}
