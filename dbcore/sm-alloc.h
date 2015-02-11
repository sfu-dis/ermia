#pragma once
#include <sched.h>
#include <numa.h>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <vector>
#include <future>
#include <new>
#include "sm-defs.h"
#include "epoch.h"
#include "../macros.h"

typedef epoch_mgr::epoch_num epoch_num;

namespace RA {
    void *allocate(uint64_t size);
    void deallocate(void* p);

    struct thread_data {
        bool initialized;
		uint64_t nbytes;
		uint64_t counts;
    };

    epoch_mgr::tls_storage *get_tls(void*);
    void global_init(void*);
    void* thread_registered(void*);
    void thread_deregistered(void *cookie, void *thread_cookie);
    void* epoch_ended(void *cookie, epoch_num e);
    void* epoch_ended_thread(void *cookie, void *epoch_cookie, void *thread_cookie);
    void epoch_reclaimed(void *cookie, void *epoch_cookie);

	void ra_register();
	void ra_deregister();
	bool ra_is_registered();
    void epoch_enter(void);
    void epoch_exit(void);
    void epoch_thread_quiesce(void);
    void init();
    extern LSN trim_lsn;
};

class scoped_ra_region {
public:
    scoped_ra_region(void)
    {
        RA::epoch_enter();
    }

    ~scoped_ra_region(void)
    {
        RA::epoch_exit();
    }
};
