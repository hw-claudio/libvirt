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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Authors: Osier Yang <jyang redhat com>
 *
 */

#include <config.h>

#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <wait.h>
#include <sys/stat.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "kvmtool_conf.h"
#include "kvmtool_driver.h"
#include "memory.h"
#include "util.h"
#include "nodeinfo.h"
#include "uuid.h"
#include "hooks.h"
#include "virfile.h"
#include "virpidfile.h"
#include "fdstream.h"
#include "domain_audit.h"

#define VIR_FROM_THIS VIR_FROM_KVMTOOL

#define START_POSTFIX ": starting up\n"
#define SHUTDOWN_POSTFIX ": shutting down\n"

#define KVMTOOL_NB_MEM_PARAM  3

static kvmtool_driver_t *kvmtool_driver = NULL;

typedef struct _kvmtoolDomainObjPrivate kvmtoolDomainObjPrivate;
typedef kvmtoolDomainObjPrivate *kvmtoolDomainObjPrivatePtr;
struct _kvmtoolDomainObjPrivate {
    /* For future use, as long as kvmtool tool provide APIs to talk
     * with the guest socket directly
     */
    int monitor;
};

static int kvmtoolStartup(int privileged);
static int kvmtoolShutdown(void);

static void kvmtoolDomainEventFlush(int timer, void *opaque);
static void kvmtoolDomainEventQueue(kvmtool_driver_t *driver,
                                    virDomainEventPtr event);

static int kvmtoolProcessAutoDestroyInit(kvmtool_driver_t *driver);
static void kvmtoolProcessAutoDestroyRun(kvmtool_driver_t *driver,
                                         virConnectPtr conn);
static void kvmtoolProcessAutoDestroyShutdown(kvmtool_driver_t *driver);
static int kvmtoolProcessAutoDestroyAdd(kvmtool_driver_t *driver,
                                        virDomainObjPtr vm,
                                        virConnectPtr conn);
static int kvmtoolProcessAutoDestroyRemove(kvmtool_driver_t *driver,
                                           virDomainObjPtr vm);

static void
kvmtoolDriverLock(kvmtool_driver_t *driver)
{
    virMutexLock(&driver->lock);
}
static void
kvmtoolDriverUnlock(kvmtool_driver_t *driver)
{
    virMutexUnlock(&driver->lock);
}

static void *
kvmtoolDomainObjPrivateAlloc(void)
{
    kvmtoolDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    priv->monitor = -1;

    return priv;
}

static void
kvmtoolDomainObjPrivateFree(void *data)
{
    kvmtoolDomainObjPrivatePtr priv = data;

    VIR_FREE(priv);
}

static virDrvOpenStatus
kvmtoolOpen(virConnectPtr conn,
            virConnectAuthPtr auth ATTRIBUTE_UNUSED,
            unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Verify uri was specified */
    if (conn->uri == NULL) {
        if (kvmtool_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI(kvmtool_driver->privileged ?
                                "kvmtool:///system":
                                "kvmtool:///session");
        if (!conn->uri) {
            virReportOOMError();
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "kvmtool"))
            return VIR_DRV_OPEN_DECLINED;

        /* Leave for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        if (conn->uri->path == NULL) {
            kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                         _("no KVMTOOL URI path given, try %s"),
                         kvmtool_driver->privileged ?
                         "kvmtool:///system" :
                         "kvmtool:///session");
                return VIR_DRV_OPEN_ERROR;
        }

        if (kvmtool_driver->privileged) {
            if (STRNEQ (conn->uri->path, "/system") &&
                STRNEQ (conn->uri->path, "/session")) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                             _("unexpected KVMTOOL URI path blu '%s', try kvmtool:///system"),
                             conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (STRNEQ (conn->uri->path, "/session")) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                             _("unexpected KVMTOOL URI path bla '%s', try kvmtool:///session"),
                             conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        }

        /* URI was good, but driver isn't active */
        if (kvmtool_driver == NULL) {
            kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("kvmtool state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    conn->privateData = kvmtool_driver;
    return VIR_DRV_OPEN_SUCCESS;
}

static int
kvmtoolClose(virConnectPtr conn)
{
    kvmtool_driver_t *driver = conn->privateData;

    kvmtoolDriverLock(driver);
    virDomainEventCallbackListRemoveConn(conn,
                                         driver->domainEventState->callbacks);
    kvmtoolProcessAutoDestroyRun(driver, conn);
    kvmtoolDriverUnlock(driver);

    conn->privateData = NULL;
    return 0;
}

static int
kvmtoolIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int
kvmtoolIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}

static char *
kvmtoolGetCapabilities(virConnectPtr conn)
{
    kvmtool_driver_t *driver = conn->privateData;
    char *xml;

    kvmtoolDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError();
    kvmtoolDriverUnlock(driver);

    return xml;
}

static virDomainPtr
kvmtoolDomainLookupByID(virConnectPtr conn, int id)
{
    kvmtool_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching id %d"), id);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr
kvmtoolDomainLookupByUUID(virConnectPtr conn,
                          const unsigned char *uuid)
{
    kvmtool_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr
kvmtoolDomainLookupByName(virConnectPtr conn,
                          const char *name)
{
    kvmtool_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    kvmtoolDriverUnlock(driver);
    if (!vm) {
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching name '%s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}


static int
kvmtoolDomainIsActive(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    kvmtoolDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int
kvmtoolDomainIsPersistent(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    kvmtoolDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int
kvmtoolDomainIsUpdated(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    kvmtoolDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = obj->updated;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int
kvmtoolListDomains(virConnectPtr conn, int *ids, int nids) {
    kvmtool_driver_t *driver = conn->privateData;
    int n;

    kvmtoolDriverLock(driver);
    n = virDomainObjListGetActiveIDs(&driver->domains, ids, nids);
    kvmtoolDriverUnlock(driver);

    return n;
}

static int
kvmtoolNumOfDomains(virConnectPtr conn) {
    kvmtool_driver_t *driver = conn->privateData;
    int n;

    kvmtoolDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    kvmtoolDriverUnlock(driver);

    return n;
}

static int
kvmtoolListDefinedDomains(virConnectPtr conn,
                          char **const names, int nnames) {
    kvmtool_driver_t *driver = conn->privateData;
    int n;

    kvmtoolDriverLock(driver);
    n = virDomainObjListGetInactiveNames(&driver->domains, names, nnames);
    kvmtoolDriverUnlock(driver);

    return n;
}


static int
kvmtoolNumOfDefinedDomains(virConnectPtr conn) {
    kvmtool_driver_t *driver = conn->privateData;
    int n;

    kvmtoolDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    kvmtoolDriverUnlock(driver);

    return n;
}

static virDomainPtr
kvmtoolDomainDefine(virConnectPtr conn, const char *xml)
{
    kvmtool_driver_t *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int dupVM;

    kvmtoolDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        1 << VIR_DOMAIN_VIRT_KVMTOOL,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if ((dupVM = virDomainObjIsDuplicate(&driver->domains, def, 0)) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, def, false)))
        goto cleanup;

    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !dupVM ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    kvmtoolDriverUnlock(driver);
    return dom;
}

static int
kvmtoolDomainUndefineFlags(virDomainPtr dom,
                           unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(driver->configDir,
                              driver->autostartDir,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int kvmtoolDomainUndefine(virDomainPtr dom)
{
    return kvmtoolDomainUndefineFlags(dom, 0);
}

static int
kvmtoolDomainGetInfo(virDomainPtr dom,
                     virDomainInfoPtr info)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    info->state = virDomainObjGetState(vm, NULL);

    if (!virDomainObjIsActive(vm)) {
        info->memory = vm->def->mem.cur_balloon;
    } else {
        /* XXX: Should query the balloon information instead
         * as long as kvmtool tool supports it
         */
        info->memory = 0;
    }

    if (driver->cgroup) {
        if (virCgroupForDomain(driver->cgroup,
                               vm->def->name,
                               &cgroup, 0) != 0) {
            kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("Unable to get cgroup for %s"), vm->def->name);
            goto cleanup;
        }

        if (virCgroupGetCpuacctUsage(cgroup, &(info->cpuTime)) < 0) {
            kvmtoolError(VIR_ERR_OPERATION_FAILED,
                     "%s", _("Cannot read cputime for domain"));
            goto cleanup;
        }
    } else {
        info->cpuTime = 0;
    }

    info->maxMem = vm->def->mem.max_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    kvmtoolDriverUnlock(driver);
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
kvmtoolDomainGetState(virDomainPtr dom,
                      int *state,
                      int *reason,
                      unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *
kvmtoolGetOSType(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = strdup(vm->def->os.type);

    if (ret == NULL)
        virReportOOMError();

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

/* Returns max memory in kb, or 0 if error */
static unsigned long
kvmtoolDomainGetMaxMemory(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long ret = 0;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
kvmtoolDomainSetMemoryFlags(virDomainPtr dom,
                            unsigned long newmem,
                            unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1, r;
    bool isActive;
    virCommandPtr cmd = NULL;
    char *errbuf = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags == VIR_DOMAIN_MEM_MAXIMUM) {
        if (isActive)
            flags |= VIR_DOMAIN_MEM_MAXIMUM;
        else
            flags |= VIR_DOMAIN_MEM_MAXIMUM;
    }

    if (!isActive && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("domain is not running"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("cannot change persistent config of a "
                           "transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* Resize the maximum memory */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("cannot resize the maximum memory on an "
                           "active domain"));
            goto cleanup;
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            persistentDef->mem.max_balloon = newmem;
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto cleanup;
        }
    } else {
        /* Resize the current memory */
        if (newmem > vm->def->mem.max_balloon) {
            kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                         _("cannot set memory higher than max memory"));
            goto cleanup;
        }

        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            cmd = virCommandNew(vm->def->emulator);
            virCommandAddEnvPassCommon(cmd);
            virCommandAddEnvFormat(cmd, "KVMTOOL_STATE_DIR=%s", driver->stateDir);
            virCommandAddArgList(cmd, "balloon", "--name", vm->def->name, NULL);

            if (newmem > vm->def->mem.cur_balloon)
                virCommandAddArg(cmd, "--inflate");
            else
                virCommandAddArg(cmd, "--deflate");

            /* kvmtool balloon command use MB. */
            virCommandAddArgFormat(cmd, "%lu", newmem / 1024);

            virCommandSetErrorBuffer(cmd, &errbuf);

            r = virCommandRun(cmd, NULL);

            virDomainAuditMemory(vm, vm->def->mem.cur_balloon, newmem, "update",
                                 r == 1);
            if (r < 0) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to balloon memory: %s"),
                             errbuf);
                goto cleanup;
            }
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(errbuf);
    virCommandFree(cmd);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int
kvmtoolDomainSetMemory(virDomainPtr dom, unsigned long newmem)
{
    return kvmtoolDomainSetMemoryFlags(dom, newmem, VIR_DOMAIN_AFFECT_LIVE);
}

static int
kvmtoolDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    return kvmtoolDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_MAXIMUM);
}

static int
kvmtoolDomainSetMemoryParameters(virDomainPtr dom,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr cgroup = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                             _("invalid type for memory hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetMemoryHardLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory hard_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                             _("invalid type for memory soft_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetMemorySoftLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory soft_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                             _("invalid type for swap_hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetMemSwapHardLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set swap_hard_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE)) {
            kvmtoolError(VIR_ERR_INVALID_ARG,
                         _("Memory tunable `%s' not implemented"), param->field);
            ret = -1;
        } else {
            kvmtoolError(VIR_ERR_INVALID_ARG,
                         _("Parameter `%s' not supported"), param->field);
            ret = -1;
        }
    }

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int
kvmtoolDomainGetMemoryParameters(virDomainPtr dom,
                                 virTypedParameterPtr params,
                                 int *nparams,
                                 unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr cgroup = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;
    int rc;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = KVMTOOL_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }
    if ((*nparams) < KVMTOOL_NB_MEM_PARAM) {
        kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                     _("Invalid parameter count"));
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("Unable to get cgroup for %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < KVMTOOL_NB_MEM_PARAM; i++) {
        virTypedParameterPtr param = &params[i];
        val = 0;
        param->value.ul = 0;
        param->type = VIR_TYPED_PARAM_ULLONG;

        switch(i) {
        case 0: /* fill memory hard limit here */
            rc = virCgroupGetMemoryHardLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory hard limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT) == NULL) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Field memory hard limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        case 1: /* fill memory soft limit here */
            rc = virCgroupGetMemorySoftLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory soft limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT) == NULL) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Field memory soft limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        case 2: /* fill swap hard limit here */
            rc = virCgroupGetMemSwapHardLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get swap hard limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT) == NULL) {
                kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Field swap hard limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        default:
            break;
            /* should not hit here */
        }
    }

    *nparams = KVMTOOL_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static char *
kvmtoolDomainGetXMLDesc(virDomainPtr dom,
                        unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             flags);
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int
kvmtoolProcessAutoDestroyInit(kvmtool_driver_t *driver)
{
    if (!(driver->autodestroy = virHashCreate(5, NULL)))
        return -1;

    return 0;
}

static int
kvmtoolDomainDestroyHelper(kvmtool_driver_t *driver,
                           virDomainObjPtr vm,
                           virDomainShutoffReason reason)
{
    virCgroupPtr cgroup;
    kvmtoolDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *logfile = NULL;
    int logfd = -1;
    const char *timestamp = NULL;
    char ebuf[1024];
    char *sockpath = NULL;
    char *errbuf = NULL;

    cmd = virCommandNew(vm->def->emulator);
    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvFormat(cmd, "KVMTOOL_STATE_DIR=%s", driver->stateDir);
    virCommandAddArgList(cmd, "stop", "-n", vm->def->name, NULL);
    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virAsprintf(&logfile, "%s/%s.log", driver->logDir,
        vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if ((logfd = open(logfile, O_WRONLY | O_APPEND)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    if ((timestamp = virTimestamp()) == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, SHUTDOWN_POSTFIX, strlen(SHUTDOWN_POSTFIX)) < 0) {
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    if (priv->monitor)
        VIR_FORCE_CLOSE(priv->monitor);

    if (virCommandRun(cmd, NULL) < 0) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("Failed to destroy domain '%s': %s"),
                     vm->def->name, errbuf);
        goto cleanup;
    }

    if (virAsprintf(&sockpath, "%s/%s.sock", driver->stateDir,
                    vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* It's up to kvmtool to remove the socket. What we can do
     * is just to report a warning if it still exists. */
    if (virFileExists(sockpath))
        VIR_WARN("The domain socket still exists after destroyed");

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_KVMTOOL)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_KVMTOOL, vm->def->name,
                    VIR_HOOK_KVMTOOL_OP_STOPPED, VIR_HOOK_SUBOP_END, NULL, xml);
        VIR_FREE(xml);
    }

    /* Stop autodestroy in case guest is restarted */
    kvmtoolProcessAutoDestroyRemove(driver, vm);

    virDomainDeleteConfig(driver->stateDir, NULL, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    vm->def->id = -1;
    priv->monitor = -1;

    if (driver->cgroup &&
        virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) == 0) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }

    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(logfile);
    VIR_FREE(timestamp);
    VIR_FREE(sockpath);
    VIR_FREE(errbuf);
    if (logfd)
        VIR_FORCE_CLOSE(logfd);
    return ret;
}

struct kvmtoolProcessAutoDestroyData {
    kvmtool_driver_t *driver;
    virConnectPtr conn;
};

static void
kvmtoolProcessAutoDestroyDom(void *payload,
                             const void *name,
                             void *opaque)
{
    struct kvmtoolProcessAutoDestroyData *data = opaque;
    virConnectPtr conn = payload;
    const char *uuidstr = name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainObjPtr dom;
    virDomainEventPtr event = NULL;

    VIR_DEBUG("conn=%p uuidstr=%s thisconn=%p", conn, uuidstr, data->conn);

    if (data->conn != conn)
        return;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        VIR_WARN("Failed to parse %s", uuidstr);
        return;
    }

    if (!(dom = virDomainFindByUUID(&data->driver->domains,
                                    uuid))) {
        VIR_DEBUG("No domain object to kill");
        return;
    }

    VIR_DEBUG("Killing domain");
    kvmtoolDomainDestroyHelper(data->driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (dom && !dom->persistent)
        virDomainRemoveInactive(&data->driver->domains, dom);

    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        kvmtoolDomainEventQueue(data->driver, event);
    virHashRemoveEntry(data->driver->autodestroy, uuidstr);
}

/*
 * Precondition: driver is locked
 */
static void
kvmtoolProcessAutoDestroyRun(kvmtool_driver_t *driver, virConnectPtr conn)
{
    struct kvmtoolProcessAutoDestroyData data = {
        driver, conn
    };
    VIR_DEBUG("conn=%p", conn);
    virHashForEach(driver->autodestroy, kvmtoolProcessAutoDestroyDom, &data);
}

static void
kvmtoolProcessAutoDestroyShutdown(kvmtool_driver_t *driver)
{
    virHashFree(driver->autodestroy);
}

static int
kvmtoolProcessAutoDestroyAdd(kvmtool_driver_t *driver,
                             virDomainObjPtr vm,
                             virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);

    VIR_DEBUG("vm=%s uuid=%s conn=%p", vm->def->name, uuidstr, conn);

    if (virHashAddEntry(driver->autodestroy, uuidstr, conn) < 0)
        return -1;
    return 0;
}

static int
kvmtoolProcessAutoDestroyRemove(kvmtool_driver_t *driver,
                                virDomainObjPtr vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);

    VIR_DEBUG("vm=%s uuid=%s", vm->def->name, uuidstr);

    if (virHashRemoveEntry(driver->autodestroy, uuidstr) < 0)
        return -1;
    return 0;
}

static int
kvmtoolConnectDomainSocket(kvmtool_driver_t * driver,
                           virDomainObjPtr vm)
{
    char *sockpath = NULL;
    int fd;
    struct sockaddr_un addr;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to create client socket"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, sockpath) == NULL) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("Socket path %s too big for destination"), sockpath);
        goto error;
    }

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        virReportSystemError(errno, _("Failed to connect to guest "
                                      "socket '%s'"), sockpath);
        goto error;
    }

    VIR_FREE(sockpath);
    return fd;

error:
    VIR_FREE(sockpath);
    VIR_FORCE_CLOSE(fd);
    return -1;
}

static virCommandPtr
kvmtoolBuildCommandLine(kvmtool_driver_t *driver ATTRIBUTE_UNUSED,
                        virDomainObjPtr vm,
                        int logfd,
                        int masterPty)
{
    virCommandPtr cmd = NULL;
    int i;

    cmd = virCommandNew(vm->def->emulator);

    virCommandAddEnvPassCommon(cmd);

    /* kvmtool use $HOME/.kvmtool_tools as the state dir by default */
    virCommandAddEnvFormat(cmd, "KVMTOOL_STATE_DIR=%s", driver->stateDir);

    virCommandAddArg(cmd, "run");
    virCommandAddArgList(cmd, "--name", vm->def->name, NULL);

    if (!vm->def->os.kernel) {
        kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("'kernel' must be specified"));
        goto cleanup;
    }
    virCommandAddArgList(cmd, "--kernel", vm->def->os.kernel, NULL);

    if (!vm->def->ndisks) {
        kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("No disk is specified"));
        goto cleanup;
    }

    if (vm->def->os.initrd)
        virCommandAddArgList(cmd, "--initrd", vm->def->os.initrd, NULL);

    if (vm->def->os.cmdline)
        virCommandAddArgList(cmd, "--params", vm->def->os.cmdline, NULL);

    if (vm->def->mem.cur_balloon) {
        virCommandAddArg(cmd, "--mem");
        virCommandAddArgFormat(cmd, "%lu", vm->def->mem.cur_balloon / 1024);
    }

    if (vm->def->vcpus) {
        virCommandAddArg(cmd, "--cpus");
        virCommandAddArgFormat(cmd, "%u", vm->def->vcpus);
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("disk bus type must be 'virtio'"));
            goto cleanup;
        }

        if (vm->def->disks[i]->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("'device' type of disk must be 'disk'"));
            goto cleanup;
        }

        if (vm->def->disks[i]->type != VIR_DOMAIN_DISK_TYPE_FILE) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("disk type must be 'file'"));
            goto cleanup;
        }
        virCommandAddArgList(cmd, "--disk", vm->def->disks[0]->src, NULL);
    }

    if (vm->def->memballoon) {
        if (vm->def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE &&
            vm->def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("memballoon 'model' must be 'virtio'"));
            goto cleanup;
        }

        virCommandAddArg(cmd, "--balloon");
    }

    for (i = 0; i < vm->def->nfss; i++) {
        if (vm->def->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("Only supports mount filesystem type"));
            goto cleanup;
        }

        virCommandAddArg(cmd, "--9p");
        virCommandAddArgFormat(cmd, "%s,%s", vm->def->fss[i]->src,
                               vm->def->fss[i]->dst);
    }

    if (vm->def->nconsoles > 1) {
        kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Only one console is supported"));
        goto cleanup;
    }

    /* XXX: I'm lost in the XMLs for char devices, the logic
     * might need to improve here.
     */
    if (vm->def->consoles) {
        switch (vm->def->consoles[0]->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
            virCommandAddArgList(cmd, "--console", "virtio", NULL);
            break;
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            virCommandAddArgList(cmd, "--console", "serial", NULL);
            break;
        default:
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("target type of console must be 'virtio' or 'serial'"));
            goto cleanup;
        }
    } else {
        if (vm->def->nserials != 0) {
            if (vm->def->nserials > 1) {
                kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                             _("Only one serial port is supported"));
                goto cleanup;
            } else {
                virCommandAddArgList(cmd, "--console", "serial", NULL);
            }
        }
    }

    virCommandSetInputFD(cmd, masterPty);
    virCommandSetOutputFD(cmd, &masterPty);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandDaemonize(cmd);

    return cmd;
cleanup:
    if (logfd)
        VIR_FORCE_CLOSE(logfd);
    if (masterPty)
        VIR_FORCE_CLOSE(masterPty);
    virCommandFree(cmd);
    return NULL;
}

static bool
kvmtoolCgroupControllerActive(kvmtool_driver_t *driver,
                              int controller)
{
    if (driver->cgroup == NULL)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;
    if (!virCgroupMounted(driver->cgroup, controller))
        return false;
    return true;
}

static int
kvmtoolRemoveCgroup(kvmtool_driver_t *driver,
                    virDomainObjPtr vm,
                    int quiet)
{
    virCgroupPtr cgroup;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0);
    if (rc != 0) {
        if (!quiet)
            kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                         _("Unable to find cgroup for %s"),
                         vm->def->name);
        return rc;
    }

    rc = virCgroupRemove(cgroup);
    virCgroupFree(&cgroup);
    return rc;
}

static int
kvmtoolSetupCgroup(kvmtool_driver_t *driver,
                   virDomainObjPtr vm)
{
    virCgroupPtr cgroup = NULL;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 1);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to create cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

    if (vm->def->blkio.weight != 0) {
        if (kvmtoolCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            rc = virCgroupSetBlkioWeight(cgroup, vm->def->blkio.weight);
            if(rc != 0) {
                virReportSystemError(-rc,
                                     _("Unable to set io weight for domain %s"),
                                     vm->def->name);
                goto cleanup;
            }
        } else {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED,
                         _("Block I/O tuning is not available on this host"));
        }
    }

    if (vm->def->mem.hard_limit != 0 ||
        vm->def->mem.soft_limit != 0 ||
        vm->def->mem.swap_hard_limit != 0) {
        if (kvmtoolCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
            if (vm->def->mem.hard_limit != 0) {
                rc = virCgroupSetMemoryHardLimit(cgroup, vm->def->mem.hard_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set memory hard limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }
            if (vm->def->mem.soft_limit != 0) {
                rc = virCgroupSetMemorySoftLimit(cgroup, vm->def->mem.soft_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set memory soft limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }

            if (vm->def->mem.swap_hard_limit != 0) {
                rc = virCgroupSetMemSwapHardLimit(cgroup, vm->def->mem.swap_hard_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set swap hard limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }
        } else {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED,
                         _("Memory cgroup is not available on this host"));
        }
    }

    if (vm->def->cputune.shares != 0) {
        if (kvmtoolCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
            rc = virCgroupSetCpuShares(cgroup, vm->def->cputune.shares);
            if(rc != 0) {
                virReportSystemError(-rc,
                                     _("Unable to set io cpu shares for domain %s"),
                                     vm->def->name);
                goto cleanup;
            }
        } else {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED,
                         _("CPU tuning is not available on this host"));
        }
    }

    virCgroupFree(&cgroup);
    return 0;

cleanup:
    if (cgroup) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }
    return -1;
}

/**
 * kvmtoolDomainStartHelper:
 * @conn: pointer to connection
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @autoDestroy: mark the domain for auto destruction
 * @reason: reason for switching vm to running state
 *
 * Starts a vm
 *
 * Returns 0 on success or -1 in case of error
 */
static int
kvmtoolDomainStartHelper(virConnectPtr conn,
                         kvmtool_driver_t * driver,
                         virDomainObjPtr vm,
                         bool autoDestroy,
                         virDomainRunningReason reason)
{
    int ret = -1;
    int masterPty;
    char *slavePty = NULL;
    char *logfile = NULL;
    int logfd = -1;
    off_t pos = -1;
    char ebuf[1024];
    const char *timestamp = NULL;
    virCommandPtr cmd = NULL;
    kvmtoolDomainObjPrivatePtr priv = vm->privateData;
    int retries = 100;
    char *sockpath = NULL;

    if (!driver->cgroup) {
        VIR_WARN("cgroup is not mounted");
    } else {
        if (!kvmtoolCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPUACCT)) {
            VIR_WARN("cgroup cpuacct controller is not mounted");
        }
        if (!kvmtoolCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
            VIR_WARN("cgroup cpuacct controller is not mounted");
        }
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    driver->logDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
    }

    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
                      S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    /* Open master pty */
    if (virFileOpenTty(&masterPty, &slavePty, 1) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to allocate tty"));
        goto cleanup;
    }

    VIR_DEBUG("masterPty = %d, slavePty = %s", masterPty, slavePty);

    if (vm->def->consoles) {
        if (vm->def->consoles[0]->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
            kvmtoolError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("Only PTY console type is supported"));
            goto cleanup;
        }

        VIR_FREE(vm->def->consoles[0]->source.data.file.path);
        vm->def->consoles[0]->source.data.file.path = slavePty;

        VIR_FREE(vm->def->consoles[0]->info.alias);
        if (virAsprintf(&vm->def->consoles[0]->info.alias, "console%d", 0) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    }

    kvmtoolRemoveCgroup(driver, vm, 1);

    /* Now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_KVMTOOL)) {
        char *xml = virDomainDefFormat(vm->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_KVMTOOL, vm->def->name,
                    VIR_HOOK_KVMTOOL_OP_START, VIR_HOOK_SUBOP_BEGIN, NULL, xml);
        VIR_FREE(xml);

         /* If the script raised an error abort the launch. */
        if (hookret < 0)
            goto cleanup;
    }

    /* Log timestamp */
    if ((timestamp = virTimestamp()) == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, START_POSTFIX, strlen(START_POSTFIX)) < 0) {
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    if (!(cmd = kvmtoolBuildCommandLine(driver, vm, logfd, masterPty)))
        goto cleanup;

    /* Log generated command line */
    virCommandWriteArgLog(cmd, logfd);

    if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));

    if (virAsprintf(&sockpath, "%s/%s.sock", driver->stateDir,
                    vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    /* Wait for guest socket shows up. */
    while (!virFileExists(sockpath) && retries) {
        usleep(100*100);
        retries--;
    }

    /* Check if could connect to the kvmtool guest socket */
    if ((priv->monitor = kvmtoolConnectDomainSocket(driver, vm)) < 0)
        goto cleanup;

    if (kvmtoolSetupCgroup(driver, vm) < 0)
        goto cleanup;

    vm->def->id = driver->nextvmid++;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    if (autoDestroy &&
        kvmtoolProcessAutoDestroyAdd(driver, vm, conn) < 0)
        goto cleanup;

    if (virDomainObjSetDefTransient(driver->caps, vm, false) < 0)
        goto cleanup;

    /* Write domain status to disk. */
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virCommandFree(cmd);
    if (ret == -1)
        VIR_FORCE_CLOSE(priv->monitor);
    VIR_FREE(logfile);
    VIR_FREE(sockpath);
    VIR_FREE(timestamp);
    return ret;
}

/**
 * kvmtoolDomainStartWithFlags:
 * @dom: domain to start
 * @flags: Must be 0 for now
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int
kvmtoolDomainStartWithFlags(virDomainPtr dom,
                            unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Domain is already running"));
        goto cleanup;
    }

    ret = kvmtoolDomainStartHelper(dom->conn, driver, vm,
                                   (flags & VIR_DOMAIN_START_AUTODESTROY),
                                   VIR_DOMAIN_RUNNING_BOOTED);

    if (ret == 0) {
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
        virDomainAuditStart(vm, "booted", true);
    } else {
        virDomainAuditStart(vm, "booted", false);
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    kvmtoolDriverUnlock(driver);
    return ret;
}

/**
 * kvmtoolDomainStart:
 * @dom: domain to start
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int kvmtoolDomainStart(virDomainPtr dom)
{
    return kvmtoolDomainStartWithFlags(dom, 0);
}

/**
 * kvmtoolDomainCreateAndStart:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: Must be 0 for now
 *
 * Creates a domain based on xml and starts it
 *
 * Returns 0 on success or -1 in case of error
 */
static virDomainPtr
kvmtoolDomainCreateAndStart(virConnectPtr conn,
                            const char *xml,
                            unsigned int flags) {
    kvmtool_driver_t *driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, NULL);

    kvmtoolDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        1 << VIR_DOMAIN_VIRT_KVMTOOL,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, def, false)))
        goto cleanup;
    def = NULL;

    if (kvmtoolDomainStartHelper(conn, driver, vm,
                             (flags & VIR_DOMAIN_START_AUTODESTROY),
                             VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        virDomainAuditStart(vm, "booted", false);
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    kvmtoolDriverUnlock(driver);
    return dom;
}


static int
kvmtoolDomainEventRegister(virConnectPtr conn,
                           virConnectDomainEventCallback callback,
                           void *opaque,
                           virFreeCallback freecb)
{
    kvmtool_driver_t *driver = conn->privateData;
    int ret;

    kvmtoolDriverLock(driver);
    ret = virDomainEventCallbackListAdd(conn,
                                        driver->domainEventState->callbacks,
                                        callback, opaque, freecb);
    kvmtoolDriverUnlock(driver);

    return ret;
}


static int
kvmtoolDomainEventDeregister(virConnectPtr conn,
                             virConnectDomainEventCallback callback)
{
    kvmtool_driver_t *driver = conn->privateData;
    int ret;

    kvmtoolDriverLock(driver);
    ret = virDomainEventStateDeregister(conn,
                                        driver->domainEventState,
                                        callback);
    kvmtoolDriverUnlock(driver);

    return ret;
}


static int
kvmtoolDomainEventRegisterAny(virConnectPtr conn,
                              virDomainPtr dom,
                              int eventID,
                              virConnectDomainEventGenericCallback callback,
                              void *opaque,
                              virFreeCallback freecb)
{
    kvmtool_driver_t *driver = conn->privateData;
    int ret;

    kvmtoolDriverLock(driver);
    ret = virDomainEventCallbackListAddID(conn,
                                          driver->domainEventState->callbacks,
                                          dom, eventID,
                                          callback, opaque, freecb);
    kvmtoolDriverUnlock(driver);

    return ret;
}


static int
kvmtoolDomainEventDeregisterAny(virConnectPtr conn,
                                int callbackID)
{
    kvmtool_driver_t *driver = conn->privateData;
    int ret;

    kvmtoolDriverLock(driver);
    ret = virDomainEventStateDeregisterAny(conn,
                                           driver->domainEventState,
                                           callbackID);
    kvmtoolDriverUnlock(driver);

    return ret;
}


static void
kvmtoolDomainEventDispatchFunc(virConnectPtr conn,
                               virDomainEventPtr event,
                               virConnectDomainEventGenericCallback cb,
                               void *cbopaque,
                               void *opaque)
{
    kvmtool_driver_t *driver = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    kvmtoolDriverUnlock(driver);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    kvmtoolDriverLock(driver);
}


static void
kvmtoolDomainEventFlush(int timer ATTRIBUTE_UNUSED,
                        void *opaque)
{
    kvmtool_driver_t *driver = opaque;

    kvmtoolDriverLock(driver);
    virDomainEventStateFlush(driver->domainEventState,
                             kvmtoolDomainEventDispatchFunc,
                             driver);
    kvmtoolDriverUnlock(driver);
}


/* driver must be locked before calling */
static void
kvmtoolDomainEventQueue(kvmtool_driver_t *driver,
                        virDomainEventPtr event)
{
    virDomainEventStateQueue(driver->domainEventState, event);
}

/**
 * kvmtoolDomainDestroyFlags:
 * @dom: pointer to domain to destroy
 * @flags: an OR'ed set of virDomainDestroyFlags
 *
 * Sends SIGKILL to container root process to terminate the container
 *
 * Returns 0 on success or -1 in case of error
 */
static int
kvmtoolDomainDestroyFlags(virDomainPtr dom,
                          unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Domain is not running"));
        goto cleanup;
    }

    ret = kvmtoolDomainDestroyHelper(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    virDomainAuditStop(vm, "destroyed");
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    kvmtoolDriverUnlock(driver);
    return ret;
}

/**
 * kvmtoolDomainDestroy:
 * @dom: pointer to domain to destroy
 *
 * Sends SIGKILL to container root process to terminate the container
 *
 * Returns 0 on success or -1 in case of error
 */
static int
kvmtoolDomainDestroy(virDomainPtr dom)
{
    return kvmtoolDomainDestroyFlags(dom, 0);
}

struct kvmtoolAutostartData {
    kvmtool_driver_t *driver;
    virConnectPtr conn;
};

static void
kvmtoolAutostartDomain(void *payload,
                       const void *name ATTRIBUTE_UNUSED,
                       void *opaque)
{
    virDomainObjPtr vm = payload;
    const struct kvmtoolAutostartData *data = opaque;

    virDomainObjLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        int ret = kvmtoolDomainStartHelper(data->conn, data->driver, vm, false,
                                       VIR_DOMAIN_RUNNING_BOOTED);
        virDomainAuditStart(vm, "booted", ret >= 0);
        if (ret < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : "");
        } else {
            virDomainEventPtr event =
                virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                kvmtoolDomainEventQueue(data->driver, event);
        }
    }
    virDomainObjUnlock(vm);
}

static void
kvmtoolAutostartConfigs(kvmtool_driver_t *driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen(driver->privileged ?
                                        "kvmtool:///system" :
                                        "kvmtool:///session");
    /* Ignoring NULL conn which is mostly harmless here */

    struct kvmtoolAutostartData data = { driver, conn };

    kvmtoolDriverLock(driver);
    virHashForEach(driver->domains.objs, kvmtoolAutostartDomain, &data);
    kvmtoolDriverUnlock(driver);

    if (conn)
        virConnectClose(conn);
}

static void
kvmtoolReconnectVM(void *payload,
                   const void *name ATTRIBUTE_UNUSED,
                   void *opaque)
{
    virDomainObjPtr vm = payload;
    kvmtool_driver_t *driver = opaque;
    kvmtoolDomainObjPrivatePtr priv;
    virCgroupPtr cgroup = NULL;

    virDomainObjLock(vm);
    VIR_DEBUG("Reconnect %d %d %d\n", vm->def->id, vm->pid, vm->state.state);

    priv = vm->privateData;

    if ((priv->monitor = kvmtoolConnectDomainSocket(driver, vm)) < 0)
        goto cleanup;

    vm->def->id = driver->nextvmid++;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNKNOWN);

    virDomainObjUnlock(vm);
    return;

cleanup:
    kvmtoolProcessAutoDestroyRemove(driver, vm);

    virDomainDeleteConfig(driver->stateDir, NULL, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);

    vm->def->id = -1;
    priv->monitor = -1;

    if (driver->cgroup &&
        virCgroupForDomain(driver->cgroup, vm->def->name,
                           &cgroup, 0) == 0) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }

    virDomainAuditStop(vm, "failed");
    virDomainObjUnlock(vm);
    return;
}

#define KVM_DEV "/dev/kvm"

static int
kvmtoolStartup(int privileged)
{
    int ret = -1;

    if (access(KVM_DEV, F_OK) != 0) {
        VIR_INFO("Host doesn't support hardware virt: %s is "
                 " not available", KVM_DEV);
        return 0;
    }

    if (VIR_ALLOC(kvmtool_driver) < 0) {
        return -1;
    }
    if (virMutexInit(&kvmtool_driver->lock) < 0) {
        VIR_FREE(kvmtool_driver);
        return -1;
    }
    kvmtoolDriverLock(kvmtool_driver);

    kvmtool_driver->privileged = privileged;
    kvmtool_driver->nextvmid = 1;

    if (virDomainObjListInit(&kvmtool_driver->domains) < 0)
        goto cleanup;

    kvmtool_driver->domainEventState = virDomainEventStateNew(kvmtoolDomainEventFlush,
                                                              kvmtool_driver,
                                                              NULL,
                                                              true);
    if (!kvmtool_driver->domainEventState)
        goto cleanup;

    ret = virCgroupForDriver("kvmtool", &kvmtool_driver->cgroup, privileged, 1);
    if (ret < 0) {
        char buf[1024] ATTRIBUTE_UNUSED;
        VIR_DEBUG("Unable to create cgroup for KVMTOOL driver: %s",
                  virStrerror(-ret, buf, sizeof(buf)));
        /* Don't abort startup. We will explicitly report to
         * the user when they try to start a VM
         */
    }

    /* Setup the directories */
    if (privileged) {
        if ((kvmtool_driver->configDir = strdup(KVMTOOL_CONFIG_DIR)) == NULL)
            goto out_of_memory;

        if ((kvmtool_driver->stateDir = strdup(KVMTOOL_STATE_DIR)) == NULL)
            goto out_of_memory;

        if ((kvmtool_driver->logDir = strdup(KVMTOOL_LOG_DIR)) == NULL)
            goto out_of_memory;

        if ((kvmtool_driver->autostartDir = strdup(KVMTOOL_AUTOSTART_DIR)) == NULL)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
        char *base = NULL;
        char *userdir = virGetUserDirectory(uid);
        if (!userdir)
            goto cleanup;

        if (virAsprintf(&kvmtool_driver->logDir,
                        "%s/.libvirt/kvmtool/log", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);

        if (virAsprintf(&kvmtool_driver->stateDir, "%s/kvmtool/run", base) == -1) {
            VIR_FREE(base);
            goto out_of_memory;
        }

        if (virAsprintf(&kvmtool_driver->configDir, "%s/kvmtool", base) == -1) {
            VIR_FREE(base);
            goto out_of_memory;
        }

        if (virAsprintf(&kvmtool_driver->autostartDir,
                        "%s/kvmtool/autostart", base) == -1) {
            VIR_FREE(base);
            goto out_of_memory;
        }
    }

    if (virFileMakePath(kvmtool_driver->logDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to create log directory '%s'"),
                             kvmtool_driver->logDir);
        goto cleanup;
    }

    if (virFileMakePath(kvmtool_driver->stateDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to create log directory '%s'"),
                             kvmtool_driver->logDir);
        goto cleanup;
    }

    if (virFileMakePath(kvmtool_driver->configDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to create log directory '%s'"),
                             kvmtool_driver->logDir);
        goto cleanup;
    }

    if (virFileMakePath(kvmtool_driver->autostartDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to create log directory '%s'"),
                             kvmtool_driver->logDir);
        goto cleanup;
    }

    if ((kvmtool_driver->caps = kvmtoolCapsInit()) == NULL)
        goto cleanup;

    kvmtool_driver->caps->privateDataAllocFunc = kvmtoolDomainObjPrivateAlloc;
    kvmtool_driver->caps->privateDataFreeFunc = kvmtoolDomainObjPrivateFree;

    if (kvmtoolProcessAutoDestroyInit(kvmtool_driver) < 0)
        goto cleanup;

    /* Get all the running persistent or transient configs first */
    if (virDomainLoadAllConfigs(kvmtool_driver->caps,
                                &kvmtool_driver->domains,
                                kvmtool_driver->stateDir,
                                NULL,
                                1, 1 << VIR_DOMAIN_VIRT_KVMTOOL,
                                NULL, NULL) < 0)
        goto cleanup;

    virHashForEach(kvmtool_driver->domains.objs, kvmtoolReconnectVM, kvmtool_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(kvmtool_driver->caps,
                                &kvmtool_driver->domains,
                                kvmtool_driver->configDir,
                                kvmtool_driver->autostartDir,
                                0, 1 << VIR_DOMAIN_VIRT_KVMTOOL,
                                NULL, NULL) < 0)
        goto cleanup;

    kvmtoolDriverUnlock(kvmtool_driver);

    kvmtoolAutostartConfigs(kvmtool_driver);

    return 0;

out_of_memory:
    virReportOOMError();
cleanup:
    kvmtoolDriverUnlock(kvmtool_driver);
    kvmtoolShutdown();
    return -1;
}

static void kvmtoolNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    kvmtool_driver_t *driver = opaque;

    if (newVM) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
            kvmtoolDomainEventQueue(driver, event);
    }
}

/**
 * kvmtoolReload:
 *
 * Function to restart the KVMTOOL driver, it will recheck the configuration
 * files and perform autostart
 */
static int
kvmtoolReload(void) {
    if (!kvmtool_driver)
        return 0;

    kvmtoolDriverLock(kvmtool_driver);
    virDomainLoadAllConfigs(kvmtool_driver->caps,
                            &kvmtool_driver->domains,
                            kvmtool_driver->configDir,
                            kvmtool_driver->autostartDir,
                            0, 1 << VIR_DOMAIN_VIRT_KVMTOOL,
                            kvmtoolNotifyLoadDomain, kvmtool_driver);
    kvmtoolDriverUnlock(kvmtool_driver);

    kvmtoolAutostartConfigs(kvmtool_driver);

    return 0;
}

static int
kvmtoolShutdown(void)
{
    if (kvmtool_driver == NULL)
        return -1;

    kvmtoolDriverLock(kvmtool_driver);
    virDomainObjListDeinit(&kvmtool_driver->domains);
    virDomainEventStateFree(kvmtool_driver->domainEventState);

    kvmtoolProcessAutoDestroyShutdown(kvmtool_driver);

    virCapabilitiesFree(kvmtool_driver->caps);
    VIR_FREE(kvmtool_driver->configDir);
    VIR_FREE(kvmtool_driver->autostartDir);
    VIR_FREE(kvmtool_driver->stateDir);
    VIR_FREE(kvmtool_driver->logDir);
    kvmtoolDriverUnlock(kvmtool_driver);
    virMutexDestroy(&kvmtool_driver->lock);
    VIR_FREE(kvmtool_driver);

    return 0;
}

/**
 * kvmtoolIsActive:
 *
 * Checks if the KVMTOOL daemon is active, i.e. has an active domain
 *
 * Returns 1 if active, 0 otherwise
 */
static int
kvmtoolIsActive(void) {
    int active;

    if (kvmtool_driver == NULL)
        return(0);

    kvmtoolDriverLock(kvmtool_driver);
    active = virDomainObjListNumOfDomains(&kvmtool_driver->domains, 1);
    kvmtoolDriverUnlock(kvmtool_driver);

    return active;
}

/*
 * kvmtoolGetVersion
 *
 * XXX: This API might be just broken currently, as kvmtool tool still
 * doesn't have a formal version, the upstream kvmtool tool will output
 * things like "3.0.rc5.873.gb73216" by "./kvmtool version".
 */
static int
kvmtoolGetVersion(virConnectPtr conn, unsigned long *version)
{
    kvmtool_driver_t *driver = conn->privateData;
    virCommandPtr cmd = NULL;
    char *outbuf = NULL;
    char *errbuf = NULL;
    const char *emulator = NULL;
    struct utsname ut;
    struct stat sb;
    char *p = NULL;
    int ret = -1;
    int i;

    uname(&ut);

    for (i = 0; i < driver->caps->nguests; i++) {
        if (STREQ(driver->caps->guests[i]->arch.name, ut.machine)) {
            emulator = driver->caps->guests[i]->arch.defaultInfo.emulator;
            break;
        }
    }

    if (!emulator) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("can't find the emulator for '%s'"),
                     ut.machine);
        goto cleanup;
    }

    if (stat(emulator, &sb) < 0) {
        virReportSystemError(errno,
                             _("Cannot stat KVMTOOL binary %s"),
                             emulator);
        goto cleanup;
    }

    cmd = virCommandNewArgList(emulator, "version", NULL);
    virCommandAddEnvPassCommon(cmd);
    virCommandSetOutputBuffer(cmd, &outbuf);
    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virCommandRun(cmd, NULL) < 0) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("Failed to get kvmtool version: %s"),
                     errbuf);
        goto cleanup;
    }

    p = strrchr(outbuf, ' ');
    p++;

    if (virParseVersionString(p, version, true) < 0) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR, _("Unknown release: %s"), p);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(outbuf);
    VIR_FREE(errbuf);
    return ret;
}

static char *kvmtoolGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED,
                                     int *nparams)
{
    char *schedulerType = NULL;

    if (nparams)
        *nparams = 1;

    schedulerType = strdup("posix");

    if (schedulerType == NULL)
        virReportOOMError();

    return schedulerType;
}

static int
kvmtoolSetSchedulerParametersFlags(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   unsigned int flags)
{
    kvmtool_driver_t *driver = domain->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (driver->cgroup == NULL)
        return -1;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STRNEQ(param->field, "cpu_shares")) {
            kvmtoolError(VIR_ERR_INVALID_ARG,
                         _("Invalid parameter `%s'"), param->field);
            goto cleanup;
        }

        if (param->type != VIR_TYPED_PARAM_ULLONG) {
            kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                         _("Invalid type for cpu_shares tunable, expected a 'ullong'"));
            goto cleanup;
        }

        int rc = virCgroupSetCpuShares(group, params[i].value.ul);
        if (rc != 0) {
            virReportSystemError(-rc, _("failed to set cpu_shares=%llu"),
                                 params[i].value.ul);
            goto cleanup;
        }

        vm->def->cputune.shares = params[i].value.ul;
    }
    ret = 0;

cleanup:
    kvmtoolDriverUnlock(driver);
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
kvmtoolSetSchedulerParameters(virDomainPtr domain,
                              virTypedParameterPtr params,
                              int nparams)
{
    return kvmtoolSetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int
kvmtoolGetSchedulerParametersFlags(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int *nparams,
                                   unsigned int flags)
{
    kvmtool_driver_t *driver = domain->conn->privateData;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;

    virCheckFlags(0, -1);

    if (driver->cgroup == NULL)
        return -1;

    if (*nparams < 1) {
        kvmtoolError(VIR_ERR_INVALID_ARG, "%s",
                     _("Invalid parameter count"));
        return -1;
    }

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0)
        goto cleanup;

    if (virCgroupGetCpuShares(group, &val) != 0)
        goto cleanup;
    params[0].value.ul = val;
    if (virStrcpyStatic(params[0].field, "cpu_shares") == NULL) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Field cpu_shares too big for destination"));
        goto cleanup;
    }
    params[0].type = VIR_TYPED_PARAM_ULLONG;

    *nparams = 1;
    ret = 0;

cleanup:
    kvmtoolDriverUnlock(driver);
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
kvmtoolGetSchedulerParameters(virDomainPtr domain,
                              virTypedParameterPtr params,
                              int *nparams)
{
    return kvmtoolGetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int
kvmtoolDomainGetAutostart(virDomainPtr dom,
                          int *autostart)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    kvmtoolDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
kvmtoolDomainSetAutostart(virDomainPtr dom,
                          int autostart)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart) {
        ret = 0;
        goto cleanup;
    }

    configFile = virDomainConfigFile(driver->configDir,
                                     vm->def->name);
    if (configFile == NULL)
        goto cleanup;
    autostartLink = virDomainConfigFile(driver->autostartDir,
                                        vm->def->name);
    if (autostartLink == NULL)
        goto cleanup;

    if (autostart) {
        if (virFileMakePath(driver->autostartDir) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create autostart directory %s"),
                                 driver->autostartDir);
            goto cleanup;
        }

        if (symlink(configFile, autostartLink) < 0) {
            virReportSystemError(errno,
                                 _("Failed to create symlink '%s to '%s'"),
                                 autostartLink, configFile);
            goto cleanup;
        }
    } else {
        if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            virReportSystemError(errno,
                                 _("Failed to delete symlink '%s'"),
                                 autostartLink);
            goto cleanup;
        }
    }

    vm->autostart = autostart;
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int
kvmtoolDomainSuspend(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *errbuf = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        cmd = virCommandNew(vm->def->emulator);
        virCommandAddEnvPassCommon(cmd);
        virCommandAddEnvFormat(cmd, "KVMTOOL_STATE_DIR=%s", driver->stateDir);
        virCommandAddArgList(cmd, "pause", "--name", vm->def->name, NULL);

        virCommandSetErrorBuffer(cmd, &errbuf);

        if (virCommandRun(cmd, NULL) < 0) {
            kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to suspend domain '%s': %s"),
                         vm->def->name, errbuf);
            goto cleanup;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    VIR_FREE(errbuf);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int
kvmtoolDomainResume(virDomainPtr dom)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *errbuf = NULL;

    kvmtoolDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);
        cmd = virCommandNew(vm->def->emulator);
        virCommandAddEnvPassCommon(cmd);
        virCommandAddEnvFormat(cmd, "KVMTOOL_STATE_DIR=%s", driver->stateDir);
        virCommandAddArgList(cmd, "resume", "--name", vm->def->name, NULL);

        virCommandSetErrorBuffer(cmd, &errbuf);

        if (virCommandRun(cmd, NULL) < 0) {
            kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to resume domain '%s': %s"),
                         vm->def->name, errbuf);
            goto cleanup;
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(errbuf);
    if (event)
        kvmtoolDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

static int
kvmtoolDomainOpenConsole(virDomainPtr dom,
                         const char *dev_name,
                         virStreamPtr st,
                         unsigned int flags)
{
    kvmtool_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ret = -1;
    virDomainChrDefPtr chr = NULL;

    virCheckFlags(0, -1);

    kvmtoolDriverLock(driver);
    virUUIDFormat(dom->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        kvmtoolError(VIR_ERR_NO_DOMAIN,
                     _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        kvmtoolError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("domain is not running"));
        goto cleanup;
    }

    if (dev_name) {
        if (vm->def->consoles[0]->info.alias &&
            STREQ(vm->def->consoles[0]->info.alias, dev_name)) {
            chr = vm->def->consoles[0];
        }
    } else {
        if (vm->def->consoles)
            chr = vm->def->consoles[0];
        else if (vm->def->nserials)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("cannot find console device '%s'"),
                     dev_name ? dev_name : _("default"));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        VIR_WARN("%d", chr->source.type);
        kvmtoolError(VIR_ERR_INTERNAL_ERROR,
                     _("character device %s is not using a PTY"), dev_name);
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    kvmtoolDriverUnlock(driver);
    return ret;
}

/* Function Tables */
static virDriver kvmtoolDriver = {
    .no = VIR_DRV_KVMTOOL,
    .name = "KVMTOOL",
    .open = kvmtoolOpen, /* 0.4.2 */
    .close = kvmtoolClose, /* 0.4.2 */
    .version = kvmtoolGetVersion, /* 0.4.6 */
    .getHostname = virGetHostname, /* 0.6.3 */
    .nodeGetInfo = nodeGetInfo, /* 0.6.5 */
    .getCapabilities = kvmtoolGetCapabilities, /* 0.6.5 */
    .listDomains = kvmtoolListDomains, /* 0.4.2 */
    .numOfDomains = kvmtoolNumOfDomains, /* 0.4.2 */
    .domainCreateXML = kvmtoolDomainCreateAndStart, /* 0.4.4 */
    .domainLookupByID = kvmtoolDomainLookupByID, /* 0.4.2 */
    .domainLookupByUUID = kvmtoolDomainLookupByUUID, /* 0.4.2 */
    .domainLookupByName = kvmtoolDomainLookupByName, /* 0.4.2 */
    .domainSuspend = kvmtoolDomainSuspend, /* 0.7.2 */
    .domainResume = kvmtoolDomainResume, /* 0.7.2 */
    .domainDestroy = kvmtoolDomainDestroy, /* 0.4.4 */
    .domainDestroyFlags = kvmtoolDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = kvmtoolGetOSType, /* 0.4.2 */
    .domainGetMaxMemory = kvmtoolDomainGetMaxMemory, /* 0.7.2 */
    .domainSetMaxMemory = kvmtoolDomainSetMaxMemory, /* 0.7.2 */
    .domainSetMemory = kvmtoolDomainSetMemory, /* 0.7.2 */
    .domainSetMemoryFlags = kvmtoolDomainSetMemoryFlags, /* 0.9.0 */
    .domainSetMemoryParameters = kvmtoolDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = kvmtoolDomainGetMemoryParameters, /* 0.8.5 */
    .domainGetInfo = kvmtoolDomainGetInfo, /* 0.4.2 */
    .domainGetState = kvmtoolDomainGetState, /* 0.9.2 */
    .domainGetXMLDesc = kvmtoolDomainGetXMLDesc, /* 0.4.2 */
    .listDefinedDomains = kvmtoolListDefinedDomains, /* 0.4.2 */
    .numOfDefinedDomains = kvmtoolNumOfDefinedDomains, /* 0.4.2 */
    .domainCreate = kvmtoolDomainStart, /* 0.4.4 */
    .domainCreateWithFlags = kvmtoolDomainStartWithFlags, /* 0.8.2 */
    .domainDefineXML = kvmtoolDomainDefine, /* 0.4.2 */
    .domainUndefine = kvmtoolDomainUndefine, /* 0.4.2 */
    .domainUndefineFlags = kvmtoolDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = kvmtoolDomainGetAutostart, /* 0.7.0 */
    .domainSetAutostart = kvmtoolDomainSetAutostart, /* 0.7.0 */
    .domainGetSchedulerType = kvmtoolGetSchedulerType, /* 0.5.0 */
    .domainGetSchedulerParameters = kvmtoolGetSchedulerParameters, /* 0.5.0 */
    .domainGetSchedulerParametersFlags = kvmtoolGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = kvmtoolSetSchedulerParameters, /* 0.5.0 */
    .domainSetSchedulerParametersFlags = kvmtoolSetSchedulerParametersFlags, /* 0.9.2 */
    .nodeGetCPUStats = nodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = nodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = nodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = nodeGetFreeMemory, /* 0.6.5 */
    .domainEventRegister = kvmtoolDomainEventRegister, /* 0.7.0 */
    .domainEventDeregister = kvmtoolDomainEventDeregister, /* 0.7.0 */
    .isEncrypted = kvmtoolIsEncrypted, /* 0.7.3 */
    .isSecure = kvmtoolIsSecure, /* 0.7.3 */
    .domainIsActive = kvmtoolDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = kvmtoolDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = kvmtoolDomainIsUpdated, /* 0.8.6 */
    .domainEventRegisterAny = kvmtoolDomainEventRegisterAny, /* 0.8.0 */
    .domainEventDeregisterAny = kvmtoolDomainEventDeregisterAny, /* 0.8.0 */
    .domainOpenConsole = kvmtoolDomainOpenConsole, /* 0.8.6 */
};

static virStateDriver kvmtoolStateDriver = {
    .name = "KVMTOOL",
    .initialize = kvmtoolStartup,
    .cleanup = kvmtoolShutdown,
    .active = kvmtoolIsActive,
    .reload = kvmtoolReload,
};

int kvmtoolRegister(void)
{
    virRegisterDriver(&kvmtoolDriver);
    virRegisterStateDriver(&kvmtoolStateDriver);
    return 0;
}
