//
//  PackagesViewController.m
//  houdini
//
//  Created by Abraham Masri on 11/13/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#import "PackagesViewController.h"
#include "ViewPackageViewController.h"
#include "sploit.h"
#include "package.h"
#include "utilities.h"
#include "packages_control.h"
#include <spawn.h>
#include <sys/sysctl.h>

@implementation PackageCell

@synthesize package = _package;

- (void) setPackage:(Package *)__package {
    _package = __package;
}

- (IBAction)packageCellButtonTapped:(id)sender {
    
}
- (void)setSelected:(BOOL)selected animated:(BOOL)animated {
    [super setSelected:selected animated:NO];
    [self setSelectedBackgroundView:[[UIView alloc] init]];
}

@end



@interface PackagesViewController ()

@property (weak, nonatomic) IBOutlet UIButton *optionsButton;
@property (weak, nonatomic) IBOutlet UISearchBar *searchBar;

@property (weak, nonatomic) IBOutlet UITableView *packagesTableView;

@end

@implementation PackagesViewController


NSString *packagesType = @"utilities";
extern NSMutableArray *tweaks_list;
extern NSMutableArray *themes_list;

NSMutableArray *utilities_list;

NSMutableArray *filtered_list;
bool is_filtered = false;


- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSArray *searchBarSubViews = [[self.searchBar.subviews objectAtIndex:0] subviews];
    for (UIView *view in searchBarSubViews) {
        if([view isKindOfClass:[UITextField class]])
        {
            UITextField *textField = (UITextField*)view;
            UIImageView *imgView = (UIImageView*)textField.leftView;
            imgView.image = [imgView.image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
            imgView.tintColor = [UIColor whiteColor];
            
            UIButton *btnClear = (UIButton*)[textField valueForKey:@"clearButton"];
            [btnClear setImage:[btnClear.imageView.image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate] forState:UIControlStateNormal];
            btnClear.tintColor = [UIColor whiteColor];
            
            
            [textField setTextColor:[UIColor whiteColor]];
        }
    }
    [self.searchBar reloadInputViews];
    
    UITextField *searchTextField = [self.searchBar valueForKey:@"_searchField"];
    if ([searchTextField respondsToSelector:@selector(setAttributedPlaceholder:)]) {
        [searchTextField setAttributedPlaceholder:[[NSAttributedString alloc] initWithString:@"Search Packages" attributes:@{NSForegroundColorAttributeName: [UIColor whiteColor]}]];
    }
    
    
    if(tweaks_list == NULL) {
        tweaks_list = [[NSMutableArray alloc] init];
    }
    
    if(themes_list == NULL) {
        themes_list = [[NSMutableArray alloc] init];
    }
    
    filtered_list = [[NSMutableArray alloc] init];
    
    utilities_list = [[NSMutableArray alloc] init];
    
    Package *display = [[Package alloc] initWithName:@"Screen Resolution" type:@"utilities" short_desc:@"Change resolution of your display" url:nil];
    Package *icons_renamer = [[Package alloc] initWithName:@"Icons Label Hide/Renamer" type:@"utilities" short_desc:@"Rename or hide your homescreen icons' labels" url:nil];
    Package *icons_shortcut_renamer = [[Package alloc] initWithName:@"Icons 3D Touch Hide/Renamer" type:@"utilities" short_desc:@"Rename or hide your homescreen 3D touch labels" url:nil];
    Package *passcode_buttons = [[Package alloc] initWithName:@"Passcode Buttons Customizer" type:@"utilities" short_desc:@"Make authentication great again!" url:nil];
    Package *colorize_badges = [[Package alloc] initWithName:@"Icon Badges" type:@"utilities" short_desc:@"Colorize and resize icon badges!" url:nil];
    Package *control_center_modules = [[Package alloc] initWithName:@"Control Center Toggles" type:@"utilities" short_desc:@"Reorder toggles and add blank ones!" url:nil];
    Package *blank_icons = [[Package alloc] initWithName:@"Blank Icons" type:@"utilities" short_desc:@"Add blank icons to your home screen" url:nil];
    Package *widgets = [[Package alloc] initWithName:@"Widgets" type:@"utilities" short_desc:@"Add widgets to your home/lock screen" url:nil];
    
    [colorize_badges setThumbnail_image:[UIImage imageNamed:@"Badge"]];
    [display setThumbnail_image:[UIImage imageNamed:@"Resize"]];
    
    [utilities_list addObject:display];
    [utilities_list addObject:icons_renamer];
    [utilities_list addObject:icons_shortcut_renamer];
    [utilities_list addObject:passcode_buttons];
    [utilities_list addObject:colorize_badges];
    [utilities_list addObject:control_center_modules];
    [utilities_list addObject:blank_icons];
//    [utilities_list addObject:widgets];
    
    // iOS 10 packages - only
    if ([[[UIDevice currentDevice] systemVersion] containsString:@"10"]) {
        
        Package *siri_suggestions = [[Package alloc] initWithName:@"Siri Suggestions" type:@"utilities" short_desc:@"(10.2.x only) Add and edit siri suggestions" url:nil];
        
        
        [utilities_list addObject:siri_suggestions];
    }
    
    // iOS 11 packages - only
    if (![[[UIDevice currentDevice] systemVersion] containsString:@"10"] && ![[[UIDevice currentDevice] systemVersion] containsString:@"11.2"]) { // no root access
            
        Package *icons_shapes = [[Package alloc] initWithName:@"Icon Shapes" type:@"utilities" short_desc:@"Change icons shapes!" url:nil];
        Package *ads_control = [[Package alloc] initWithName:@"Ads Blocker" type:@"utilities" short_desc:@"Block ads system-wide" url:nil];
        Package *emojis = [[Package alloc] initWithName:@"Emojificator" type:@"utilities" short_desc:@"Change Emoji font" url:nil];
        Package *bootlogos = [[Package alloc] initWithName:@"BetterBootLogos" type:@"utilities" short_desc:@"Change the boring Apple bootlogo" url:nil];
        
        
        [icons_shapes setThumbnail_image:[UIImage imageNamed:@"Shape"]];
        [ads_control setThumbnail_image:[UIImage imageNamed:@"Ads"]];
        [emojis setThumbnail_image:[UIImage imageNamed:@"Emoji"]];
        [bootlogos setThumbnail_image:[UIImage imageNamed:@"BootLogo"]];
        
        [utilities_list addObject:icons_shapes];
        [utilities_list addObject:ads_control];
        [utilities_list addObject:emojis];
        [utilities_list addObject:bootlogos];
        
    }
    
    // iPhone X packages - only
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *modelChar = malloc(size);
    sysctlbyname("hw.machine", modelChar, &size, NULL, 0);
    NSString *deviceModel = [NSString stringWithUTF8String:modelChar];
    free(modelChar);
    if ([deviceModel isEqualToString:@"iPhone10,3"] | [deviceModel isEqualToString:@"iPhone10,6"]) {
        Package *iamanimoji = [[Package alloc] initWithName:@"IamAnimoji" type:@"utilities" short_desc:@"Add your face to Animoji! (iPhone X only)" url:nil];
        
        [iamanimoji setThumbnail_image:[UIImage imageNamed:@"Animoji"]];
        
        [utilities_list addObject:iamanimoji];
    }
}

- (void) viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    
    [self.packagesTableView reloadData];
}



- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if(is_filtered) {
        return [filtered_list count];
    }
    
    if([packagesType  isEqual: @"tweaks"]) {
        return [tweaks_list count];
    } else if ([packagesType  isEqual: @"themes"]) {
        return [themes_list count];
    } else if ([packagesType  isEqual: @"utilities"]) {
        return [utilities_list count];
    }
    return [tweaks_list count];
}


- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    PackageCell *cell = (PackageCell *)[tableView dequeueReusableCellWithIdentifier:@"PackageCell"];
    
    Package *package = NULL;
    
    if(is_filtered) {
        
        package = (Package *)[filtered_list objectAtIndex:indexPath.row];
        
    } else {
        
        if([packagesType isEqual: @"tweaks"]) {
            package = (Package *)[tweaks_list objectAtIndex:indexPath.row];
        } else if ([packagesType  isEqual: @"themes"]) {
            package = (Package *)[themes_list objectAtIndex:indexPath.row];
        } else if ([packagesType  isEqual: @"utilities"]) {
            package = (Package *)[utilities_list objectAtIndex:indexPath.row];
        }  else {
            
        }
    }
    
    [cell.packageTitle setText:[package get_name]];
    
    if(package.source != nil)
        [cell.packageSource setText:[NSString stringWithFormat:@"from %@", package.source.name]];
    else
        [cell.packageSource setText:@""];
    
    [cell.packageDesc setText:[package get_short_desc]];
    
    if([package get_thumbnail_image] != nil) {
        [cell.packageIcon setImage:[package get_thumbnail_image]];
    } else {
        if([package.type containsString: @"tweak"]) {
            [cell.packageIcon setImage:[UIImage imageNamed:@"Tweak"]];
        } else if ([package.type containsString: @"theme"]) {
            [cell.packageIcon setImage:[UIImage imageNamed:@"Theme"]];
        } else if ([package.type containsString: @"utilities"]) {
            [cell.packageIcon setImage:[UIImage imageNamed:@"Utility"]];
        }
    }
    [cell.imageView setContentMode:UIViewContentModeScaleAspectFit];
    cell.package = package;
    cell.mainViewController = self;
    
    return cell;
}

- (void)scrollViewWillBeginDragging:(UIScrollView *)scrollView {
    [self.searchBar resignFirstResponder];
}

- (void) tableView: (UITableView *) tableView didSelectRowAtIndexPath: (NSIndexPath *) indexPath {
    
    PackageCell *cell = (PackageCell *)[tableView cellForRowAtIndexPath:indexPath];
    
    if([cell.package.type containsString:@"utilities"]) { // utilities are custom
        
        // this is not the way to do it. move it to a config file or something..
        if([cell.package.name isEqual: @"Screen Resolution"])
            [self presentViewControllerWithIdentifier:@"DisplayViewController"];
        else if([cell.package.name isEqual: @"Icons Label Hide/Renamer"])
            [self presentViewControllerWithIdentifier:@"IconsRenamerViewController"];
        else if([cell.package.name isEqual: @"Icons 3D Touch Hide/Renamer"])
            [self presentViewControllerWithIdentifier:@"IconsShortcutRenamerViewController"];
        else if([cell.package.name isEqual: @"Siri Suggestions"])
            [self presentViewControllerWithIdentifier:@"SiriSuggestionsViewController"];
        else if([cell.package.name isEqual: @"Passcode Buttons Customizer"])
            [self presentViewControllerWithIdentifier:@"PasscodeButtonsViewController"];
        else if([cell.package.name isEqual: @"Icon Badges"])
            [self presentViewControllerWithIdentifier:@"ColorizeBadgesViewController"];
        else if([cell.package.name isEqual: @"Icon Shapes"])
            [self presentViewControllerWithIdentifier:@"IconShapesViewController"];
        else if([cell.package.name isEqual: @"Ads Blocker"])
            [self presentViewControllerWithIdentifier:@"AdsControlViewController"];
        else if([cell.package.name isEqual: @"Emojificator"])
            [self presentViewControllerWithIdentifier:@"EmojisViewController"];
        else if([cell.package.name isEqual: @"BetterBootLogos"])
            [self presentViewControllerWithIdentifier:@"BootlogosViewController"];
        else if([cell.package.name isEqual: @"IamAnimoji"])
            [self presentViewControllerWithIdentifier:@"IamAnimojiViewController"];
        else if([cell.package.name isEqual: @"Control Center Toggles"])
            [self presentViewControllerWithIdentifier:@"ControlCenterViewController"];
        else if([cell.package.name isEqual: @"Blank Icons"])
            [self presentViewControllerWithIdentifier:@"BlankIconsViewController"];
        else if([cell.package.name isEqual: @"Widgets"])
            [self presentViewControllerWithIdentifier:@"WidgetsViewController"];
    } else
        [self presentPackageView:cell.package];
    
}

- (IBAction)packagesTypeChanged:(id)sender {

    if (self.packageTypeSegmentedControl.selectedSegmentIndex == 0) { // Tools
        packagesType = @"tools";
    } else if (self.packageTypeSegmentedControl.selectedSegmentIndex == 1) { // Themes
        packagesType = @"themes";
    } else if (self.packageTypeSegmentedControl.selectedSegmentIndex == 2) { // Utilities
        packagesType = @"utilities";
    } else { // Installed
        packagesType = @"installed";
    }
    [self.packagesTableView reloadData];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    
    [filtered_list removeAllObjects];
    
    // for now, only search themes
    if(![packagesType isEqualToString:@"themes"] || [searchText isEqualToString:@""]) {
        is_filtered = false;
        [self.packagesTableView reloadData];
        return;
    }
    
    for(Package * package in themes_list) {
        if([package.name.lowercaseString containsString:searchText.lowercaseString]) {
            [filtered_list addObject:package];
        }
    }
    
    is_filtered = true;
    [self.packagesTableView reloadData];
}

- (IBAction)presentPackagesOptionsView:(id)sender {
    
    [self presentViewControllerWithIdentifier:@"PackagesOptionsViewController"];
    
}


- (void)presentViewControllerWithIdentifier:(NSString *) identifier{
    
    [self.searchBar resignFirstResponder];
    UIViewController *packagesOptionsViewController=[self.storyboard instantiateViewControllerWithIdentifier:identifier];
    packagesOptionsViewController.providesPresentationContextTransitionStyle = YES;
    packagesOptionsViewController.definesPresentationContext = YES;
    [packagesOptionsViewController setModalPresentationStyle:UIModalPresentationOverCurrentContext];
    [self presentViewController:packagesOptionsViewController animated:YES completion:nil];
    
}

-(void)presentPackageView:(Package *) package;
{
    [self.searchBar resignFirstResponder];
    ViewPackageViewController *viewPackageViewController=[self.storyboard instantiateViewControllerWithIdentifier:@"ViewPackageViewController"];
    viewPackageViewController.providesPresentationContextTransitionStyle = YES;
    viewPackageViewController.definesPresentationContext = YES;
    [viewPackageViewController setModalPresentationStyle:UIModalPresentationOverCurrentContext];
    viewPackageViewController.package = package;
    [self presentViewController:viewPackageViewController animated:YES completion:nil];
}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch * touch = [touches anyObject];
    if(touch.phase == UITouchPhaseBegan) {
        [self.searchBar resignFirstResponder];
    }
}


@end

