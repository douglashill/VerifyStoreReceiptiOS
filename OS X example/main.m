//
//  main.m
//  Mac App Store receipts
//
//  Created by Douglas Hill on 05/12/2013.
//  Copyright (c) 2013 Douglas Hill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VerifyStoreReceipt.h"

int main(int argc, const char * argv[])
{
	@autoreleasepool {
		NSURL *url = [[NSBundle mainBundle] appStoreReceiptURL];
		NSLog(@"URL: %@", url);
		NSString *path = [url path];
		NSLog(@"Path: %@", path);
		
		if (verifyReceiptAtPath(path)) {
			NSLog(@"Verification successful.");
		}
		else {
			NSLog(@"Verification failed.");
			exit(173);
			NSLog(@"Failed to exit.");
			return 173;
		}
	}
	
    return 0;
}

