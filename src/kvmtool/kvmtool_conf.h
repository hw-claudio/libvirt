/*
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Authors: Osier Yang <jyang redhat com>
 */

#ifndef KVMTOOL_CONF_H
# define KVMTOOL_CONF_H

# include <config.h>

# include "internal.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "capabilities.h"
# include "threads.h"
# include "cgroup.h"
# include "configmake.h"

# define KVMTOOL_CONFIG_DIR SYSCONFDIR "/libvirt/kvmtool"
# define KVMTOOL_STATE_DIR LOCALSTATEDIR "/run/libvirt/kvmtool"
# define KVMTOOL_LOG_DIR LOCALSTATEDIR "/log/libvirt/kvmtool"
# define KVMTOOL_AUTOSTART_DIR KVMTOOL_CONFIG_DIR "/autostart"

typedef struct __kvmtool_driver kvmtool_driver_t;
struct __kvmtool_driver {
    virMutex lock;

    int privileged;
    int nextvmid;
    unsigned long version;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;

    virCapsPtr caps;
    virCgroupPtr cgroup;
    virDomainObjList domains;

    virDomainEventStatePtr domainEventState;
    virHashTablePtr autodestroy;
};

virCapsPtr kvmtoolCapsInit(void);

# define kvmtoolError(code, ...)                                             \
    virReportErrorHelper(VIR_FROM_KVMTOOL, code, __FILE__,                   \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#endif /* KVMTOOL_CONF_H */
