//
//  utilities.h
//  nsxpc2pc
//
//  Created by Abraham Masri on 11/17/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef utilities_h
#define utilities_h

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>


#include "remote_file.h"
#include "triple_fetch_remote_call.h"
#include "remote_memory.h"
#include "remote_ports.h"
#include "strategy_control.h"

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#define INSTALL_UID									33
#define INSTALL_GID									33

#define ROOT_UID									0
#define WHEEL_GID                                   0

#define MOBILE_UID									501
#define MOBILE_GID									501

#define PRIV_PORT()									get_priv_port()

extern strategy chosen_strategy;

mach_port_t get_priv_port();
kern_return_t set_file_permissions (char *, int, int, int);
kern_return_t copy_file(char *, char *, int, int, int);
NSString *get_houdini_dir_for_path(NSString *);

NSMutableData *get_current_wallpaper();
NSData * get_saved_wallpaper();
void kill_springboard(int);
void change_carrier_name(NSString *new_name);

const char * decompress_deb_file(char *);
char* get_houdini_app_path();

void persist_priv_port();
void show_alert(UIViewController *view_controller, NSString *title, NSString *message);

void utilities_init(mach_port_t);

#endif /* utilities_h */
