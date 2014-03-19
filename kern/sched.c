#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

#include <vmm/vmx.h>

static int
vmxon() {
    int r;
    if(!thiscpu->is_vmx_root) {
        r = vmx_init_vmxon();
        if(r < 0) {
            cprintf("Error executing VMXON: %e\n", r);
            return r;
        }
        cprintf("VMXON\n");
    }
    return 0;
}

// Choose a user environment to run and run it.
    void
sched_yield(void)
{
    struct Env *idle;
    int i;

    // Implement simple round-robin scheduling.
    //
    // Search through 'envs' for an ENV_RUNNABLE environment in
    // circular fashion starting just after the env this CPU was
    // last running.  Switch to the first such environment found.
    //
    // If no envs are runnable, but the environment previously
    // running on this CPU is still ENV_RUNNING, it's okay to
    // choose that environment.
    //
    // Never choose an environment that's currently running on
    // another CPU (env_status == ENV_RUNNING) and never choose an
    // idle environment (env_type == ENV_TYPE_IDLE).  If there are
    // no runnable environments, simply drop through to the code
    // below to switch to this CPU's idle environment.

    // Ashish

	if (curenv) {
        	for (i = ENVX(curenv->env_id)+1; i != ENVX(curenv->env_id); i = (i+1)%NENV) {
                	if (envs[i].env_type != ENV_TYPE_IDLE && 
			     #ifdef RUN_POSTPROCESS_DEDUP_ON_IDLE
			     envs[i].env_type != ENV_TYPE_GUEST &&
			     #endif
        	             envs[i].env_status == ENV_RUNNABLE)
                	        break;
	        }
		if (i != ENVX(curenv->env_id) || // Termination condition of circular queue
		    (i == ENVX(curenv->env_id) && envs[i].env_type != ENV_TYPE_IDLE &&
		    #ifdef RUN_POSTPROCESS_DEDUP_ON_IDLE
                    envs[i].env_type != ENV_TYPE_GUEST &&
		    #endif
		    envs[i].env_status == ENV_RUNNING)) // Choose only if current is in running state
			env_run(&envs[i]);
	}
    // For debugging and testing purposes, if there are no
    // runnable environments other than the idle environments,
    // drop into the kernel monitor.
    for (i = 0; i < NENV; i++) {
        if (envs[i].env_type != ENV_TYPE_IDLE && /*Ashish*/ envs[i].env_type != ENV_TYPE_GUEST &&
                (envs[i].env_status == ENV_RUNNABLE ||
                 envs[i].env_status == ENV_RUNNING)) {
            break;
        }
    }
    if (i == NENV) {
	//Ashish
	#ifdef POST_PROCESS_DEDUP
        // Run post processing env of dedup module
        for (i = 0; i < NENV; i++) {
                if (envs[i].env_type == ENV_TYPE_GUEST &&
                    (envs[i].env_status == ENV_RUNNABLE ||
                     envs[i].env_status == ENV_RUNNING)) {
                        env_run(&envs[i]);
                        break;
                }
        }
#endif
        cprintf("No more runnable environments!\n");
        while (1)
            monitor(NULL);
    }

    // Run this CPU's idle environment when nothing else is runnable.
    idle = &envs[cpunum()];
    if (!(idle->env_status == ENV_RUNNABLE || idle->env_status == ENV_RUNNING))
        panic("CPU %d: No idle environment!", cpunum());
    env_run(idle);
}
