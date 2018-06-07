//
//  WidgetObject.h
//  houdini
//
//  Created by Abraham Masri on 5/7/18.
//  Copyright © 2018 cheesecakeufo. All rights reserved.
//

#ifndef WidgetObject_h
#define WidgetObject_h

#include <Foundation/Foundation.h>

@interface WidgetObject : NSObject

@property NSString *beforeTime;
@property NSString *afterTime;

@property int hourSize;
@property BOOL hourBold;

@property int textSize;
@property BOOL textBold;

@end

#endif /* WidgetObject_h */
