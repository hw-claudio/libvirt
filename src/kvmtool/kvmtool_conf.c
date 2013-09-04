/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors: Osier Yang <jyang redhat com>
 */

#include <config.h>

#include <sys/utsname.h>

#include "kvmtool_conf.h"
#include "nodeinfo.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_KVMTOOL

static const char *
GetAlt32bitArch(const char *arch)
{
    /* Any Linux 64bit arch which has a 32bit
     * personality available should be listed here */
    if (STREQ(arch, "x86_64"))
        return "i686";
    if (STREQ(arch, "s390x"))
        return "s390";
    if (STREQ(arch, "ppc64"))
        return "ppc";
    if (STREQ(arch, "parisc64"))
        return "parisc";
    if (STREQ(arch, "sparc64"))
        return "sparc";
    if (STREQ(arch, "mips64"))
        return "mips";

    return NULL;
}

/* Functions */
virCapsPtr kvmtoolCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    const char *altArch;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine, 0, 0)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (virGetHostUUID(caps->host.host_uuid)) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("cannot get the host uuid"));
        goto error;
    }

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         utsname.machine,
                                         sizeof(void*) == 4 ? 32 : 64,
                                         KVMTOOL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvmtool",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto error;

    /* On 64-bit hosts, we can use personality() to request a 32bit process */
    if ((altArch = GetAlt32bitArch(utsname.machine)) != NULL) {
        if ((guest = virCapabilitiesAddGuest(caps,
                                             "hvm",
                                             altArch,
                                             32,
                                             KVMTOOL,
                                             NULL,
                                             0,
                                             NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          "kvmtool",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;
    }

    virCapabilitiesSetEmulatorRequired(caps);

    return caps;

error:
    virCapabilitiesFree(caps);
    return NULL;
}
