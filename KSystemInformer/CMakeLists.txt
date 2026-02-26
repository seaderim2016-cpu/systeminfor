#
# Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
#
# This file is part of System Informer.
#

project(KSystemInformer)

set(HEADERS
    "include/comms.h"
    "include/informer.h"
    "include/informer_filep.h"
    "include/kph.h"
    "include/ntfill.h"
    "include/pooltags.h"
    "include/trace.h"
)
source_group("Header Files" FILES ${HEADERS})

set(SOURCES
    "alloc.c"
    "alpc.c"
    "back_trace.c"
    "cid_table.c"
    "cid_tracking.c"
    "comms.c"
    "comms_handlers.c"
    "device.c"
    "driver.c"
    "dyndata.c"
    "dynimp.c"
    "file.c"
    "hash.c"
    "imgcoherency.c"
    "informer.c"
    "informer_debug.c"
    "informer_file.c"
    "informer_filenc.c"
    "informer_fileop.c"
    "informer_image.c"
    "informer_object.c"
    "informer_process.c"
    "informer_registry.c"
    "informer_thread.c"
    "knowndll.c"
    "kphobject.c"
    "kphthread.c"
    "lsa.c"
    "main.c"
    "object.c"
    "parameters.c"
    "process.c"
    "protection.c"
    "ratelmt.c"
    "ringbuff.c"
    "session_token.c"
    "system.c"
    "thread.c"
    "umaccess.c"
    "util.c"
    "verify.c"
    "vm.c"
    "conquer_stealth.c"
    "conquer_hooks.c"
)
source_group("Source Files" FILES ${SOURCES})

set(ALL_FILES
    ${HEADERS}
    ${SOURCES}
)

si_add_kernel_driver(KSystemInformer ${ALL_FILES})

target_include_directories(KSystemInformer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${SI_ROOT}/kphlib/include"
    "${SI_ROOT}/phnt"
)

target_link_libraries(KSystemInformer PRIVATE
    kphlib_um
    FltMgr
    ksecdd
)
