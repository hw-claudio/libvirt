/*---------------------------------------------------------------------------*/
/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
 * Copyright 2010, diateam (www.diateam.net)
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
/*---------------------------------------------------------------------------*/

#include <config.h>

#include <fcntl.h>

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "vmx.h"
#include "vmware_conf.h"
#include "vmware_driver.h"
#include "virstring.h"

static const char *vmw_types[] = { "player", "ws" };

static void
vmwareDriverLock(struct vmware_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void
vmwareDriverUnlock(struct vmware_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

static void *
vmwareDataAllocFunc(void)
{
    vmwareDomainPtr dom;

    if (VIR_ALLOC(dom) < 0)
        return NULL;

    dom->vmxPath = NULL;
    dom->gui = true;

    return dom;
}

static void
vmwareDataFreeFunc(void *data)
{
    vmwareDomainPtr dom = data;

    VIR_FREE(dom->vmxPath);
    VIR_FREE(dom);
}

static virDomainXMLOptionPtr
vmwareDomainXMLConfigInit(void)
{
    virDomainXMLPrivateDataCallbacks priv = { .alloc = vmwareDataAllocFunc,
                                              .free = vmwareDataFreeFunc };

    return virDomainXMLOptionNew(NULL, &priv, NULL);
}

static virDrvOpenStatus
vmwareConnectOpen(virConnectPtr conn,
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    struct vmware_driver *driver;
    char * vmrun = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        /* @TODO accept */
        return VIR_DRV_OPEN_DECLINED;
    } else {
        if (conn->uri->scheme == NULL ||
            (STRNEQ(conn->uri->scheme, "vmwareplayer") &&
             STRNEQ(conn->uri->scheme, "vmwarews")))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't /session, then they typoed, so tell them correct path */
        if (conn->uri->path == NULL || STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected VMware URI path '%s', try vmwareplayer:///session or vmwarews:///session"),
                           NULLSTR(conn->uri->path));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    vmrun = virFindFileInPath(VMRUN);

    if (vmrun == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s utility is missing"), VMRUN);
        return VIR_DRV_OPEN_ERROR;
    } else {
        VIR_FREE(vmrun);
    }

    if (VIR_ALLOC(driver) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (virMutexInit(&driver->lock) < 0)
        goto cleanup;

    driver->type = STRNEQ(conn->uri->scheme, "vmwareplayer") ?
      TYPE_WORKSTATION : TYPE_PLAYER;

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(driver->caps = vmwareCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = vmwareDomainXMLConfigInit()))
        goto cleanup;

    if (vmwareLoadDomains(driver) < 0)
        goto cleanup;

    if (vmwareExtractVersion(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

  cleanup:
    vmwareFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int
vmwareConnectClose(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;

    vmwareFreeDriver(driver);

    conn->privateData = NULL;

    return 0;
}

static const char *
vmwareConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "VMware";
}

static int
vmwareConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct vmware_driver *driver = conn->privateData;

    vmwareDriverLock(driver);
    *version = driver->version;
    vmwareDriverUnlock(driver);
    return 0;
}

static int
vmwareUpdateVMStatus(struct vmware_driver *driver, virDomainObjPtr vm)
{
    virCommandPtr cmd;
    char *outbuf = NULL;
    char *vmxAbsolutePath = NULL;
    char *parsedVmxPath = NULL;
    char *str;
    char *saveptr = NULL;
    bool found = false;
    int oldState = virDomainObjGetState(vm, NULL);
    int newState;
    int ret = -1;

    cmd = virCommandNewArgList(VMRUN, "-T", vmw_types[driver->type],
                               "list", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virFileResolveAllLinks(((vmwareDomainPtr) vm->privateData)->vmxPath,
                               &vmxAbsolutePath) < 0)
        goto cleanup;

    for (str = outbuf; (parsedVmxPath = strtok_r(str, "\n", &saveptr)) != NULL;
         str = NULL) {

        if (parsedVmxPath[0] != '/')
            continue;

        if (STREQ(parsedVmxPath, vmxAbsolutePath)) {
            found = true;
            /* If the vmx path is in the output, the domain is running or
             * is paused but we have no way to detect if it is paused or not. */
            if (oldState == VIR_DOMAIN_PAUSED)
                newState = oldState;
            else
                newState = VIR_DOMAIN_RUNNING;
            break;
        }
    }

    if (!found) {
        vm->def->id = -1;
        newState = VIR_DOMAIN_SHUTOFF;
    }

    virDomainObjSetState(vm, newState, 0);

    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    VIR_FREE(vmxAbsolutePath);
    return ret;
}

static int
vmwareStopVM(struct vmware_driver *driver,
             virDomainObjPtr vm,
             virDomainShutoffReason reason)
{
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINEL, "stop",
        PROGRAM_SENTINEL, "soft", NULL
    };

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);

    if (virRun(cmd, NULL) < 0) {
        return -1;
    }

    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}

static int
vmwareStartVM(struct vmware_driver *driver, virDomainObjPtr vm)
{
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINEL, "start",
        PROGRAM_SENTINEL, PROGRAM_SENTINEL, NULL
    };
    const char *vmxPath = ((vmwareDomainPtr) vm->privateData)->vmxPath;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not in shutoff state"));
        return -1;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, vmxPath);
    if (!((vmwareDomainPtr) vm->privateData)->gui)
        vmwareSetSentinal(cmd, NOGUI);
    else
        vmwareSetSentinal(cmd, NULL);

    if (virRun(cmd, NULL) < 0) {
        return -1;
    }

    if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0) {
        vmwareStopVM(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
        return -1;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    return 0;
}

static virDomainPtr
vmwareDomainDefineXML(virConnectPtr conn, const char *xml)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;

    ctx.formatFileName = vmwareCopyVMXFileName;

    vmwareDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         1 << VIR_DOMAIN_VIRT_VMWARE,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->xmlopt, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write vmx file '%s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainObjListAdd(driver->domains,
                                   vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    pDomain = vm->privateData;
    if (VIR_STRDUP(pDomain->vmxPath, vmxPath) < 0)
        goto cleanup;

    vmwareDomainConfigDisplay(pDomain, vmdef);

    vmdef = NULL;
    vm->persistent = 1;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = -1;

  cleanup:
    virDomainDefFree(vmdef);
    VIR_FREE(vmx);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    VIR_FREE(vmxPath);
    if (vm)
        virObjectUnlock(vm);
    vmwareDriverUnlock(driver);
    return dom;
}

static int
vmwareDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    vmwareDriverLock(driver);

    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (vmwareStopVM(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;
  cleanup:
    if (vm)
        virObjectUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static int
vmwareDomainShutdown(virDomainPtr dom)
{
    return vmwareDomainShutdownFlags(dom, 0);
}

static int
vmwareDomainDestroy(virDomainPtr dom)
{
    return vmwareDomainShutdownFlags(dom, 0);
}

static int
vmwareDomainDestroyFlags(virDomainPtr dom,
                         unsigned int flags)
{
    return vmwareDomainShutdownFlags(dom, flags);
}

static int
vmwareDomainSuspend(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;

    virDomainObjPtr vm;
    const char *cmd[] = {
      VMRUN, "-T", PROGRAM_SENTINEL, "pause",
      PROGRAM_SENTINEL, NULL
    };
    int ret = -1;

    if (driver->type == TYPE_PLAYER) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vmplayer does not support libvirt suspend/resume"
                         " (vmware pause/unpause) operation "));
        return ret;
    }

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);
    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
vmwareDomainResume(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;

    virDomainObjPtr vm;
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINEL, "unpause", PROGRAM_SENTINEL,
        NULL
    };
    int ret = -1;

    if (driver->type == TYPE_PLAYER) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vmplayer does not support libvirt suspend/resume "
                         "(vmware pause/unpause) operation "));
        return ret;
    }

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);
    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in suspend state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
vmwareDomainReboot(virDomainPtr dom, unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    const char * vmxPath = NULL;
    virDomainObjPtr vm;
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINEL,
        "reset", PROGRAM_SENTINEL, "soft", NULL
    };
    int ret = -1;

    virCheckFlags(0, -1);

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    vmxPath = ((vmwareDomainPtr) vm->privateData)->vmxPath;
    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, vmxPath);

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
vmwareDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;

    virCheckFlags(0, NULL);

    ctx.formatFileName = vmwareCopyVMXFileName;

    vmwareDriverLock(driver);

    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         1 << VIR_DOMAIN_VIRT_VMWARE,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->xmlopt, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write vmx file '%s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainObjListAdd(driver->domains,
                                   vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    pDomain = vm->privateData;
    if (VIR_STRDUP(pDomain->vmxPath, vmxPath) < 0)
        goto cleanup;

    vmwareDomainConfigDisplay(pDomain, vmdef);
    vmdef = NULL;

    if (vmwareStartVM(driver, vm) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(vmdef);
    VIR_FREE(vmx);
    VIR_FREE(vmxPath);
    if (vm)
        virObjectUnlock(vm);
    vmwareDriverUnlock(driver);
    return dom;
}

static int
vmwareDomainCreateWithFlags(virDomainPtr dom,
                            unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = vmwareStartVM(driver, vm);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static int
vmwareDomainCreate(virDomainPtr dom)
{
    return vmwareDomainCreateWithFlags(dom, 0);
}

static int
vmwareDomainUndefineFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static int
vmwareDomainUndefine(virDomainPtr dom)
{
    return vmwareDomainUndefineFlags(dom, 0);
}

static virDomainPtr
vmwareDomainLookupByID(virConnectPtr conn, int id)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByID(driver->domains, id);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static char *
vmwareDomainGetOSType(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, vm->def->os.type));

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static virDomainPtr
vmwareDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
vmwareDomainLookupByName(virConnectPtr conn, const char *name)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, name);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int
vmwareDomainIsActive(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    vmwareDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

  cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}


static int
vmwareDomainIsPersistent(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    vmwareDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

  cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}


static char *
vmwareDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(vm->def, flags);

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
vmwareConnectDomainXMLFromNative(virConnectPtr conn, const char *nativeFormat,
                                 const char *nativeConfig,
                                 unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    virVMXContext ctx;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (STRNEQ(nativeFormat, "vmware-vmx")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config format '%s'"), nativeFormat);
        return NULL;
    }

    ctx.parseFileName = vmwareCopyVMXFileName;

    def = virVMXParseConfig(&ctx, driver->xmlopt, nativeConfig);

    if (def != NULL)
        xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

    virDomainDefFree(def);

    return xml;
}

static int vmwareDomainObjListUpdateDomain(virDomainObjPtr dom, void *data)
{
    struct vmware_driver *driver = data;
    virObjectLock(dom);
    ignore_value(vmwareUpdateVMStatus(driver, dom));
    virObjectUnlock(dom);
    return 0;
}

static void
vmwareDomainObjListUpdateAll(virDomainObjListPtr doms, struct vmware_driver *driver)
{
    virDomainObjListForEach(doms, vmwareDomainObjListUpdateDomain, driver);
}

static int
vmwareConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    vmwareDomainObjListUpdateAll(driver->domains, driver);
    n = virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
    vmwareDriverUnlock(driver);

    return n;
}

static int
vmwareConnectNumOfDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    vmwareDomainObjListUpdateAll(driver->domains, driver);
    n = virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
    vmwareDriverUnlock(driver);

    return n;
}


static int
vmwareConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    vmwareDomainObjListUpdateAll(driver->domains, driver);
    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids, NULL, NULL);
    vmwareDriverUnlock(driver);

    return n;
}

static int
vmwareConnectListDefinedDomains(virConnectPtr conn,
                                char **const names, int nnames)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    vmwareDomainObjListUpdateAll(driver->domains, driver);
    n = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                         NULL, NULL);
    vmwareDriverUnlock(driver);
    return n;
}

static int
vmwareDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);
    info->cpuTime = 0;
    info->maxMem = vm->def->mem.max_balloon;
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
vmwareDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    vmwareDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
vmwareConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
vmwareConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    vmwareDriverLock(driver);
    vmwareDomainObjListUpdateAll(driver->domains, driver);
    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 NULL, flags);
    vmwareDriverUnlock(driver);
    return ret;
}



static virDriver vmwareDriver = {
    .no = VIR_DRV_VMWARE,
    .name = "VMWARE",
    .connectOpen = vmwareConnectOpen, /* 0.8.7 */
    .connectClose = vmwareConnectClose, /* 0.8.7 */
    .connectGetType = vmwareConnectGetType, /* 0.8.7 */
    .connectGetVersion = vmwareConnectGetVersion, /* 0.8.7 */
    .connectListDomains = vmwareConnectListDomains, /* 0.8.7 */
    .connectNumOfDomains = vmwareConnectNumOfDomains, /* 0.8.7 */
    .connectListAllDomains = vmwareConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = vmwareDomainCreateXML, /* 0.8.7 */
    .domainLookupByID = vmwareDomainLookupByID, /* 0.8.7 */
    .domainLookupByUUID = vmwareDomainLookupByUUID, /* 0.8.7 */
    .domainLookupByName = vmwareDomainLookupByName, /* 0.8.7 */
    .domainSuspend = vmwareDomainSuspend, /* 0.8.7 */
    .domainResume = vmwareDomainResume, /* 0.8.7 */
    .domainShutdown = vmwareDomainShutdown, /* 0.8.7 */
    .domainShutdownFlags = vmwareDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = vmwareDomainReboot, /* 0.8.7 */
    .domainDestroy = vmwareDomainDestroy, /* 0.8.7 */
    .domainDestroyFlags = vmwareDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = vmwareDomainGetOSType, /* 0.8.7 */
    .domainGetInfo = vmwareDomainGetInfo, /* 0.8.7 */
    .domainGetState = vmwareDomainGetState, /* 0.9.2 */
    .domainGetXMLDesc = vmwareDomainGetXMLDesc, /* 0.8.7 */
    .connectDomainXMLFromNative = vmwareConnectDomainXMLFromNative, /* 0.9.11 */
    .connectListDefinedDomains = vmwareConnectListDefinedDomains, /* 0.8.7 */
    .connectNumOfDefinedDomains = vmwareConnectNumOfDefinedDomains, /* 0.8.7 */
    .domainCreate = vmwareDomainCreate, /* 0.8.7 */
    .domainCreateWithFlags = vmwareDomainCreateWithFlags, /* 0.8.7 */
    .domainDefineXML = vmwareDomainDefineXML, /* 0.8.7 */
    .domainUndefine = vmwareDomainUndefine, /* 0.8.7 */
    .domainUndefineFlags = vmwareDomainUndefineFlags, /* 0.9.4 */
    .domainIsActive = vmwareDomainIsActive, /* 0.8.7 */
    .domainIsPersistent = vmwareDomainIsPersistent, /* 0.8.7 */
    .connectIsAlive = vmwareConnectIsAlive, /* 0.9.8 */
};

int
vmwareRegister(void)
{
    if (virRegisterDriver(&vmwareDriver) < 0)
        return -1;
    return 0;
}
