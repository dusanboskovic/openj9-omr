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

static char corefile_name[PATH_MAX];
static int corefile_fd = -1;

static int coredump_to_file(mach_port_t, pid_t);
static int dump_threads_to_file(mach_port_t, uint32_t *, uint32_t *);

static void exit_coredump(void) {
	raise(SIGKILL);
}

static int coredump_to_file(mach_port_t task_port, pid_t pid) {
	kern_return_t kr = KERN_SUCCESS;
	struct mach_header_64 *mh64;
	struct segment_command_64 *segments = NULL;
	struct thread_command *threads = NULL;
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
	// update ncmds and sizeofcmds later when we figure out size
	mh64->ncmds = 0;
	mh64->sizeofcmds = 0;
	mh64->filetype = MH_CORE;

	pwrite(corefile_fd, mh64, sizeof(struct mach_header_64), file_off);
	fileoff += sizeof(struct mach_header_64);

	segments = NULL;
	kr = dump_threads_to_file(task_port, threads);


done:
	if (corefile_fd > 0) {
		close(corefile_fd);
	}
	return kr;
}

static int dump_threads_to_file(mach_port_t task_port, struct thread_command *threads) {
	

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