#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <poll.h>
#include <lkl_host.h>
#include "iomem.h"
#include "jmp_buf.h"

/* Let's see if the host has semaphore.h */
#include <unistd.h>

#ifdef _POSIX_SEMAPHORES
#include <semaphore.h>
/* TODO(pscollins): We don't support fork() for now, but maybe one day
 * we will? */
#define SHARE_SEM 0
#endif /* _POSIX_SEMAPHORES */
#include <semaphore.h>

static void print(const char *str, int len)
{
	int ret __attribute__((unused));

	ret = write(STDOUT_FILENO, str, len);
}

struct lkl_mutex {
	pthread_mutex_t mutex;
};

struct lkl_sem {
#ifdef _POSIX_SEMAPHORES
	sem_t sem;
#else
	pthread_mutex_t lock;
	int count;
	pthread_cond_t cond;
#endif /* _POSIX_SEMAPHORES */
};

struct lkl_tls_key {
	pthread_key_t key;
};

#define WARN_UNLESS(exp) do {						\
		if (exp < 0)						\
			lkl_printf("%s: %s\n", #exp, strerror(errno));	\
	} while (0)

static int _warn_pthread(int ret, char *str_exp)
{
	if (ret > 0)
		lkl_printf("%s: %s\n", str_exp, strerror(ret));

	return ret;
}


/* pthread_* functions use the reverse convention */
#define WARN_PTHREAD(exp) _warn_pthread(exp, #exp)

static struct lkl_sem *sem_alloc(int count)
{
	struct lkl_sem *sem;

	sem = malloc(sizeof(*sem));
	if (!sem)
		return NULL;

#ifdef _POSIX_SEMAPHORES
	if (sem_init(&sem->sem, SHARE_SEM, count) < 0) {
		lkl_printf("sem_init: %s\n", strerror(errno));
		free(sem);
		return NULL;
	}
#else
	pthread_mutex_init(&sem->lock, NULL);
	sem->count = count;
	WARN_PTHREAD(pthread_cond_init(&sem->cond, NULL));
#endif /* _POSIX_SEMAPHORES */

	return sem;
}

static void sem_free(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	WARN_UNLESS(sem_destroy(&sem->sem));
#else
	WARN_PTHREAD(pthread_cond_destroy(&sem->cond));
	WARN_PTHREAD(pthread_mutex_destroy(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
	free(sem);
}

static void sem_up(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	WARN_UNLESS(sem_post(&sem->sem));
#else
	WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
	sem->count++;
	if (sem->count > 0)
		WARN_PTHREAD(pthread_cond_signal(&sem->cond));
	WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */

}

static void sem_down(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	int err;

	do {
		err = sem_wait(&sem->sem);
	} while (err < 0 && errno == EINTR);
	if (err < 0 && errno != EINTR)
		lkl_printf("sem_wait: %s\n", strerror(errno));
#else
	WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
	while (sem->count <= 0)
		WARN_PTHREAD(pthread_cond_wait(&sem->cond, &sem->lock));
	sem->count--;
	WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
}

static struct lkl_mutex *mutex_alloc(int recursive)
{
	struct lkl_mutex *_mutex = malloc(sizeof(struct lkl_mutex));
	pthread_mutex_t *mutex = NULL;
	pthread_mutexattr_t attr;

	if (!_mutex)
		return NULL;

	mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutexattr_init(&attr));

	/* PTHREAD_MUTEX_ERRORCHECK is *very* useful for debugging,
	 * but has some overhead, so we provide an option to turn it
	 * off. */
#ifdef DEBUG
	if (!recursive)
		WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
#endif /* DEBUG */

	if (recursive)
		WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));

	WARN_PTHREAD(pthread_mutex_init(mutex, &attr));

	return _mutex;
}

static void mutex_lock(struct lkl_mutex *mutex)
{
	WARN_PTHREAD(pthread_mutex_lock(&mutex->mutex));
}

static void mutex_unlock(struct lkl_mutex *_mutex)
{
	pthread_mutex_t *mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutex_unlock(mutex));
}

static void mutex_free(struct lkl_mutex *_mutex)
{
	pthread_mutex_t *mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutex_destroy(mutex));
	free(_mutex);
}

enum Status { NOT_INTIALIZED, READY, PROCESSING, KILLED };

struct thread_creator {
  pthread_t worker_pth;
  enum Status status;
  pthread_mutex_t mp;
  pthread_cond_t worker_wakeup_cond;
  pthread_cond_t worker_finish_cond;
  pthread_cond_t waiting_thread_cond;
  
  void (*fn)(void *);
  void *arg;
  pthread_t pth;
  int rval;
};

struct thread_creator th_creator =
  {
   0,
   NOT_INTIALIZED,
   PTHREAD_MUTEX_INITIALIZER,
   PTHREAD_COND_INITIALIZER,
   PTHREAD_COND_INITIALIZER,
   PTHREAD_COND_INITIALIZER,
   0,
   0,
   0,
   0
  };

static void *thread_creator_main(void *arg) {
  pthread_mutex_lock(&th_creator.mp);
  if (th_creator.status != NOT_INTIALIZED) {
    pthread_mutex_unlock(&th_creator.mp);
    return NULL;
  }
  th_creator.status = READY;
  pthread_cond_broadcast(&th_creator.waiting_thread_cond);
  while(1) {
    pthread_cond_wait(&th_creator.worker_wakeup_cond, &th_creator.mp);
    if (th_creator.status == KILLED) {
      pthread_mutex_unlock(&th_creator.mp);
      return NULL;
    }
    if (th_creator.status == PROCESSING) {
      th_creator.rval = pthread_create(&th_creator.pth, NULL, (void* (*)(void *))th_creator.fn, th_creator.arg);
      pthread_cond_signal(&th_creator.worker_finish_cond);
    }
  }
}

static void thread_creator_init(void) {
  sigset_t ss;

  sigemptyset(&ss);
  if (sigaddset(&ss, SIGALRM) != 0) 
    return;
  if (pthread_sigmask(SIG_BLOCK, &ss, NULL) != 0) 
    return;

  pthread_create(&th_creator.worker_pth, NULL, thread_creator_main, NULL);
}

static int create_thread(pthread_t *pth, void (*fn)(void *), void *arg) {
  int rval;
  
  pthread_mutex_lock(&th_creator.mp);
  if (th_creator.status == NOT_INTIALIZED) {
     thread_creator_init();
  }
  while (th_creator.status != READY) {
    pthread_cond_wait(&th_creator.waiting_thread_cond, &th_creator.mp);
  }
  th_creator.status = PROCESSING;
  
  th_creator.fn = fn;
  th_creator.arg = arg;
  
  pthread_cond_signal(&th_creator.worker_wakeup_cond);
  pthread_cond_wait(&th_creator.worker_finish_cond, &th_creator.mp);

  *pth = th_creator.pth;
  rval = th_creator.rval;
  
  th_creator.status = READY;
  pthread_cond_signal(&th_creator.waiting_thread_cond);
  pthread_mutex_unlock(&th_creator.mp);
  return rval;
}

static void thread_creator_halt(void) {
  th_creator.status = KILLED;
  pthread_mutex_lock(&th_creator.mp);
  pthread_cond_signal(&th_creator.worker_wakeup_cond);
  pthread_mutex_unlock(&th_creator.mp);
  pthread_join(th_creator.worker_pth, NULL);
}

static lkl_thread_t thread_create(void (*fn)(void *), void *arg)
{
	pthread_t thread;
	//if (WARN_PTHREAD(pthread_create(&thread, NULL, (void* (*)(void *))fn, arg)))
	if (WARN_PTHREAD(create_thread(&thread, fn, arg)))
		return 0;
	else
		return (lkl_thread_t) thread;
}

static void thread_detach(void)
{
	WARN_PTHREAD(pthread_detach(pthread_self()));
}

static void thread_exit(void)
{
	pthread_exit(NULL);
}

static int thread_join(lkl_thread_t tid)
{
	if (WARN_PTHREAD(pthread_join((pthread_t)tid, NULL)))
		return -1;
	else
		return 0;
}

static lkl_thread_t thread_self(void)
{
	return (lkl_thread_t)pthread_self();
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b)
{
	return pthread_equal((pthread_t)a, (pthread_t)b);
}

static struct lkl_tls_key *tls_alloc(void (*destructor)(void *))
{
	struct lkl_tls_key *ret = malloc(sizeof(struct lkl_tls_key));

	if (WARN_PTHREAD(pthread_key_create(&ret->key, destructor))) {
		free(ret);
		return NULL;
	}
	return ret;
}

static void tls_free(struct lkl_tls_key *key)
{
	WARN_PTHREAD(pthread_key_delete(key->key));
	free(key);
}

static int tls_set(struct lkl_tls_key *key, void *data)
{
	if (WARN_PTHREAD(pthread_setspecific(key->key, data)))
		return -1;
	return 0;
}

static void *tls_get(struct lkl_tls_key *key)
{
	return pthread_getspecific(key->key);
}

static unsigned long long time_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return 1e9*ts.tv_sec + ts.tv_nsec;
}

struct helper_info {
  void (*fn)(void *);
  void *arg;
  struct helper_info *next;
};

struct helper_info *info_list;

void *timerhelper_func(void *arg) {
  sigset_t ss;
  sigemptyset(&ss);
  if (sigaddset(&ss, SIGALRM) != 0) 
    return NULL;
  
  while (1) {
    siginfo_t siginfo;
    if (sigwaitinfo(&ss, &siginfo) >= 0) {
      struct helper_info *i = info_list;
      while(i != NULL) {
	if ((void *)i == siginfo.si_value.sival_ptr) {
	  i->fn(i->arg);
	}
	i = i->next;
      }
    }
  }
}

pthread_mutex_t helper_th_mp = PTHREAD_MUTEX_INITIALIZER;
pthread_t helper_th = 0;

static void *timer_alloc(void (*fn)(void *), void *arg)
{
	int err;
	timer_t timer;
	
	struct helper_info *info = malloc(sizeof(struct helper_info));
	info->fn = fn;
	info->arg = arg;
	info->next = NULL;

	pthread_mutex_lock(&helper_th_mp);
	if (helper_th == 0) {
	  info_list = info;
	  create_thread(&helper_th, (void (*)(void *))timerhelper_func, NULL);
	  pthread_detach(helper_th);
	} else {
	  struct helper_info *i = info_list;
	  while(i->next != NULL) {
	    i = i->next;
	  }
	  i->next = info;
	}
	pthread_mutex_unlock(&helper_th_mp);
	
	struct sigevent se =
	  {
	   .sigev_notify = SIGEV_SIGNAL,
	   .sigev_signo = SIGALRM,
	   .sigev_value =
	   {
	    .sival_ptr = (void *)info
	   }
	  };

	err = timer_create(CLOCK_REALTIME, &se, &timer);
	if (err)
		return NULL;
	
	return (void *)(long)timer;
}

static int timer_set_oneshot(void *_timer, unsigned long ns)
{
	timer_t timer = (timer_t)(long)_timer;
	struct itimerspec ts = {
		.it_value = {
			.tv_sec = ns / 1000000000,
			.tv_nsec = ns % 1000000000,
		},
	};

	int i = timer_settime(timer, 0, &ts, NULL);
	return i;
}

static void timer_free(void *_timer)
{
	timer_t timer = (timer_t)(long)_timer;

	timer_delete(timer);
}

static void panic(void)
{
	assert(0);
}

static long _gettid(void)
{
#ifdef	__FreeBSD__
	return (long)pthread_self();
#else
	return syscall(SYS_gettid);
#endif
}

struct lkl_host_operations lkl_host_ops = {
	.panic = panic,
	.thread_create = thread_create,
	.thread_detach = thread_detach,
	.thread_exit = thread_exit,
	.thread_join = thread_join,
	.thread_self = thread_self,
	.thread_equal = thread_equal,
	.sem_alloc = sem_alloc,
	.sem_free = sem_free,
	.sem_up = sem_up,
	.sem_down = sem_down,
	.mutex_alloc = mutex_alloc,
	.mutex_free = mutex_free,
	.mutex_lock = mutex_lock,
	.mutex_unlock = mutex_unlock,
	.tls_alloc = tls_alloc,
	.tls_free = tls_free,
	.tls_set = tls_set,
	.tls_get = tls_get,
	.time = time_ns,
	.timer_alloc = timer_alloc,
	.timer_set_oneshot = timer_set_oneshot,
	.timer_free = timer_free,
	.print = print,
	.mem_alloc = malloc,
	.mem_free = free,
	.ioremap = lkl_ioremap,
	.iomem_access = lkl_iomem_access,
	.virtio_devices = lkl_virtio_devs,
	.gettid = _gettid,
	.jmp_buf_set = jmp_buf_set,
	.jmp_buf_longjmp = jmp_buf_longjmp,
};

static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
	off_t off;

	off = lseek(disk.fd, 0, SEEK_END);
	if (off < 0)
		return -1;

	*res = off;
	return 0;
}

static int do_rw(ssize_t (*fn)(), struct lkl_disk disk, struct lkl_blk_req *req)
{
	off_t off = req->sector * 512;
	void *addr;
	int len;
	int i;
	int ret = 0;

	for (i = 0; i < req->count; i++) {

		addr = req->buf[i].iov_base;
		len = req->buf[i].iov_len;

		do {
			ret = fn(disk.fd, addr, len, off);

			if (ret <= 0) {
				ret = -1;
				goto out;
			}

			addr += ret;
			len -= ret;
			off += ret;

		} while (len);
	}

out:
	return ret;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	int err = 0;

	switch (req->type) {
	case LKL_DEV_BLK_TYPE_READ:
		err = do_rw(pread, disk, req);
		break;
	case LKL_DEV_BLK_TYPE_WRITE:
		err = do_rw(pwrite, disk, req);
		break;
	case LKL_DEV_BLK_TYPE_FLUSH:
	case LKL_DEV_BLK_TYPE_FLUSH_OUT:
#ifdef __linux__
		err = fdatasync(disk.fd);
#else
		err = fsync(disk.fd);
#endif
		break;
	default:
		return LKL_DEV_BLK_STATUS_UNSUP;
	}

	if (err < 0)
		return LKL_DEV_BLK_STATUS_IOERR;

	return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
	.get_capacity = fd_get_capacity,
	.request = blk_request,
};

