//
//  multi_path_strategy.h
//  houdini
//
//  Created by Abraham Masri on 06/03/2018.
//  Copyright © 2018 cheesecakeufo. All rights reserved.
//

#ifndef multi_path_strategy
#define multi_path_strategy

#include "strategy_control.h"

//extern uint64_t kernel_base;
//extern uint64_t kernel_task;
//extern uint64_t kaslr_slide;
//
//
size_t kread(uint64_t where, void *p, size_t size);
uint64_t kread_uint64(uint64_t where);
uint32_t kread_uint32(uint64_t where);
size_t kwrite(uint64_t where, const void *p, size_t size);
size_t kwrite_uint64(uint64_t where, uint64_t value);
size_t kwrite_uint32(uint64_t where, uint32_t value);

uint64_t multi_path_get_proc_with_pid(pid_t target_pid, int spawned);
kern_return_t multi_path_post_exploit ();
void multi_path_mkdir(char *path);
void multi_path_ls(char *path);
strategy _multi_path_strategy();

#endif /* multi_path_strategy_h */
