/*******************************************************************************
 * Copyright (c) 2021, 2021 IBM Corp. and others
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] http://openjdk.java.net/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/

/**
 * @file
 * @ingroup Port
 * @brief User space dump creation for OSX
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/machine.h>
#include <mach/thread_status.h>
#include <mach/vm_region.h>
#include <mach-o/loader.h>

#include "omrport.h"
#include "omrportpriv.h"
#include "omrosdump_helpers.h"

/* full thread command for x86_64, with thread state flavors
 * currently needed for debugging
 */
struct thread_command_full_64 {
	uint32_t cmd;
	uint32_t cmdsize;
	x86_thread_state_t thread_state;
	x86_float_state_t float_state;
	x86_exception_state_t exceptions;
};

static char corefile_name[PATH_MAX];
static int corefile_fd = -1;

static int coredump_to_file(mach_port_t, pid_t);
static int list_thread_commands(mach_port_t, struct thread_command_full_64 **, natural_t *);

static void exit_coredump(void) {
	raise(SIGKILL);
}

static int coredump_to_file(mach_port_t task_port, pid_t pid) {
	kern_return_t kr = KERN_SUCCESS;
	struct mach_header_64 *mh64;
	struct segment_command_64 *segments = NULL;
	struct thread_command_full_64 *threads = NULL;
	natural_t thread_count;
	natural_t cpu_count;
    processor_basic_info_t proc_info_array;
    mach_msg_type_number_t info_count;
	off_t file_off = 0;


	int err = 0;

	corefile_fd = open(corefile_name, O_RDWR | O_CREAT | O_EXCL, 0600);

	if (-1 == corefile_fd) {
		err = errno;
		perror("open()");
		goto done;
	}

    kr = host_processor_info(mach_host_self(), PROCESSOR_BASIC_INFO, &cpu_count, (processor_info_array_t *)&proc_info_array, &info_count);
	if (kr != KERN_SUCCESS) {
		mach_error("failed to get processor info:\n", kr);
		goto done;
	}

	mh64 = calloc(1, sizeof(struct mach_header_64));
	mh64->magic = MH_MAGIC_64;
	mh64->cputype = proc_info_array[0].cpu_type;
	mh64->cpusubtype = proc_info_array[0].cpu_subtype;
	// update ncmds and sizeofcmds after processing thread and segment commands
	mh64->ncmds = 0;
	mh64->sizeofcmds = 32;
	mh64->filetype = MH_CORE;

	file_off += sizeof(struct mach_header_64);
	segments = NULL;
	kr = list_thread_commands(task_port, &threads, &thread_count);
	if (kr != KERN_SUCCESS) {
		mach_error("error getting thread command data:\n", kr);
	}

	fprintf(stderr, "write threads: size: %lu, offset: %llu\n", sizeof(struct thread_command_full_64) * thread_count, file_off);
	fprintf(stderr,"expected counts -  thread: %u, float: %u, except: %u\n", x86_THREAD_STATE64_COUNT, x86_FLOAT_STATE64_COUNT, x86_EXCEPTION_STATE64_COUNT);
	fprintf(stderr,"struct sizes -  thread: %lu, float: %lu, except: %lu, all: %lu\n", sizeof(x86_thread_state_t), sizeof(x86_float_state_t), sizeof(x86_exception_state_t), sizeof(struct thread_command_full_64));

	for (int i = 0; i < thread_count; i++) {
		fprintf(stderr, "thread %d - command %u, size: %u\n", i, threads[i].cmd, threads[i].cmdsize);
		fprintf(stderr, "  thread - threadstate %u, count: %u\n", threads[i].thread_state.tsh.flavor, threads[i].thread_state.tsh.count);
		fprintf(stderr, "  thread - floatstate %u, count: %u\n", threads[i].float_state.fsh.flavor, threads[i].float_state.fsh.count);
		fprintf(stderr, "  thread - exceptionstate %u, count: %u\n", threads[i].exceptions.esh.flavor, threads[i].exceptions.esh.count);
		pwrite(corefile_fd, &threads[i].cmd, 4, file_off);
		pwrite(corefile_fd, &threads[i].cmdsize, 4, file_off + 4);
		file_off += 8;
		pwrite(corefile_fd, &threads[i].thread_state, sizeof(x86_thread_state_t), file_off);
		file_off += sizeof(x86_thread_state_t);
		pwrite(corefile_fd, &threads[i].float_state, sizeof(x86_float_state_t), file_off);
		file_off += sizeof(x86_float_state_t);
		pwrite(corefile_fd, &threads[i].exceptions, sizeof(x86_exception_state_t), file_off);
		file_off += sizeof(x86_exception_state_t);
		mh64->sizeofcmds += threads[i].cmdsize;

	}
	mh64->ncmds += thread_count;

	//write mach header after all command number and size are known
	pwrite(corefile_fd, mh64, sizeof(struct mach_header_64), 0);



done:
	if (corefile_fd > 0) {
		close(corefile_fd);
	}
	return kr;
}

static int list_thread_commands(mach_port_t task_port, struct thread_command_full_64 **thread_commands, natural_t *thread_count) {
	kern_return_t kr = KERN_SUCCESS;
	thread_act_array_t thread_info;
	struct thread_command_full_64 *threads = NULL;

	kr = task_threads(task_port, &thread_info, thread_count);

	if (kr != KERN_SUCCESS) {
		mach_error("task_thread failed with: ", kr);
		return kr;
	}

	if (NULL == threads) {
		threads = calloc(*thread_count, sizeof(struct thread_command_full_64));
		if (NULL == threads) {
			kr = KERN_NO_SPACE;
			goto done;
		}
	}

	for (int i = 0; i < *thread_count; i++) {
		uint32_t state_int_count;
		threads[i].cmd = LC_THREAD;
		threads[i].cmdsize = 8;
		state_int_count = x86_THREAD_STATE_COUNT;
		kr = thread_get_state(thread_info[i], x86_THREAD_STATE, (thread_state_t)&threads[i].thread_state, &state_int_count);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		threads[i].cmdsize += state_int_count * 4;
		state_int_count = x86_FLOAT_STATE_COUNT;
		kr = thread_get_state(thread_info[i], x86_FLOAT_STATE, (thread_state_t)&threads[i].float_state, &state_int_count);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		threads[i].cmdsize += state_int_count * 4;
		state_int_count = x86_EXCEPTION_STATE_COUNT;
		kr = thread_get_state(thread_info[i], x86_EXCEPTION_STATE, (thread_state_t)&threads[i].exceptions, &state_int_count);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		threads[i].cmdsize += state_int_count * 4;
	}
	if (KERN_SUCCESS == kr) {
		*thread_commands = threads;
	}

done:
	for (int i = 0; i < *thread_count; i++) {
		mach_port_deallocate(mach_task_self(), thread_info[i]);
	}
	return kr;
}

/**
 * Create a dump file of the OS state.
 *
 * @param[in] portLibrary The port library.
 * @param[in] filename Buffer for filename optionally containing the filename where dump is to be output.
 * @param[out] filename filename used for dump file or error message.
 * @param[in] dumpType Type of dump to perform. Unused on OSX
 * @param[in] userData Implementation specific data. Unused on OSX
 *
 * @return 0 on success, non-zero otherwise.
 *
 * @note filename buffer can not be NULL.
 * @note user allocates and frees filename buffer.
 * @note filename buffer length is platform dependent, assumed to be EsMaxPath/MAX_PATH
 *
 * @note if filename buffer is empty, a filename will be generated.
 * @note if J9UNIQUE_DUMPS is set, filename will be unique.
 */
uintptr_t
omrdump_create(struct OMRPortLibrary *portLibrary, char *filename, char *dumpType, void *userData)
{
	pid_t parent_pid, child_pid;
	char*  lastSep = NULL;
	kern_return_t kr;
    mach_port_t pass_port = MACH_PORT_NULL;
    mach_port_t special_port = MACH_PORT_NULL;

	
	parent_pid = getpid();
	/* set core name, defaults to "core.PID" if none given */
	if (!filename || ('\0' == filename[0])) {
		snprintf(corefile_name, PATH_MAX, "core.%u", parent_pid);
	} else {
		lastSep = strrchr(filename, DIR_SEPARATOR);
		if (lastSep != NULL) {
			strncpy(corefile_name, lastSep + 1, PATH_MAX);
		} else {
			strncpy(corefile_name, filename, PATH_MAX);
		}
	}

	/* pass parent task port to child through special port inheritance */
    kr = task_get_bootstrap_port(mach_task_self(), &special_port);
    if(kr != KERN_SUCCESS) {
        mach_error("failed get special port:\n", kr);
        return kr;
    }
    pass_port = mach_task_self();
    kr = task_set_bootstrap_port(mach_task_self(), pass_port);
    if(kr != KERN_SUCCESS) {
        mach_error("failed set special port:\n", kr);
        return kr;
    }	

	child_pid = fork();
	if (0 == child_pid) {
 		child_pid = getpid();
        kr = task_get_bootstrap_port(mach_task_self(), &pass_port);
        if(kr != KERN_SUCCESS) {
            mach_error("failed get special port:\n", kr);
            return kr;
        }
        task_suspend(pass_port);

		kr = coredump_to_file(pass_port, parent_pid);
		task_resume(pass_port);
		exit_coredump();
	} else {
		waitpid(child_pid, NULL, 0);
        kr = task_set_bootstrap_port(mach_task_self(), special_port);
        if(kr != KERN_SUCCESS)
        {
            mach_error("failed set special port:\n", kr);
            return kr;
        }
	}

	return kr;	
}

int32_t
omrdump_startup(struct OMRPortLibrary *portLibrary)
{
	return 0;
}

void
omrdump_shutdown(struct OMRPortLibrary *portLibrary)
{
}