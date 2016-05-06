//
//  validatereceipt.m
//
//  Based on validatereceipt.m
//  Created by Ruotger Skupin on 23.10.10.
//  Copyright 2010-2011 Matthew Stevens, Ruotger Skupin, Apple, Dave Carlton, Fraser Hess, anlumo, David Keegan, Alessandro Segala. All rights reserved.
//
//  Modified for iOS, converted to ARC, and added additional fields by Rick Maddy 2013-08-20
//  Copyright 2013 Rick Maddy. All rights reserved.
//

/*
 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 
 Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 
 Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in
 the documentation and/or other materials provided with the distribution.
 
 Neither the name of the copyright holders nor the names of its contributors may be used to endorse or promote products derived
 from this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "VerifyStoreReceipt.h"

// link with Foundation.framework, Security.framework, libssl and libCrypto (via -lssl -lcrypto in Other Linker Flags)

#import <Security/Security.h>

#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/err.h>


#ifndef YES_I_HAVE_READ_THE_WARNING_AND_I_ACCEPT_THE_RISK

#warning --- DON'T USE THIS CODE AS IS! IF EVERYONE USES THE SAME CODE
#warning --- IT IS PRETTY EASY TO BUILD AN AUTOMATIC CRACKING TOOL
#warning --- FOR APPS USING THIS CODE!
#warning --- BY USING THIS CODE YOU ACCEPT TAKING THE RESPONSIBILITY FOR
#warning --- ANY DAMAGE!
#warning ---
#warning --- YOU HAVE BEEN WARNED!

// if you want to take that risk, add "-DYES_I_HAVE_READ_THE_WARNING_AND_I_ACCEPT_THE_RISK" in the build settings at "Other C Flags"

#endif // YES_I_HAVE_READ_THE_WARNING_AND_I_ACCEPT_THE_RISK

#define VRCFRelease(object) if(object) CFRelease(object)

#define ENABLE_RECEIPT_VERIFICATION_LOGGING 1

#if ENABLE_RECEIPT_VERIFICATION_LOGGING
#define ReceiptLog(...) NSLog(__VA_ARGS__)
#else
#define ReceiptLog(...) do {} while 0
#endif

NSString *kReceiptBundleIdentifier				= @"BundleIdentifier";
NSString *kReceiptBundleIdentifierData			= @"BundleIdentifierData";
NSString *kReceiptVersion						= @"Version";
NSString *kReceiptOpaqueValue					= @"OpaqueValue";
NSString *kReceiptHash							= @"Hash";
NSString *kReceiptInApp							= @"InApp";
NSString *kReceiptOriginalVersion               = @"OrigVer";
NSString *kReceiptExpirationDate                = @"ExpDate";

NSString *kReceiptInAppQuantity					= @"Quantity";
NSString *kReceiptInAppProductIdentifier		= @"ProductIdentifier";
NSString *kReceiptInAppTransactionIdentifier	= @"TransactionIdentifier";
NSString *kReceiptInAppPurchaseDate				= @"PurchaseDate";
NSString *kReceiptInAppOriginalTransactionIdentifier	= @"OriginalTransactionIdentifier";
NSString *kReceiptInAppOriginalPurchaseDate		= @"OriginalPurchaseDate";
NSString *kReceiptInAppSubscriptionExpirationDate = @"SubExpDate";
NSString *kReceiptInAppCancellationDate         = @"CancelDate";
NSString *kReceiptInAppWebOrderLineItemID       = @"WebItemId";


/*  Obtain the Apple Inc. root certificate from http://www.apple.com/certificateauthority/
    Download the Apple Inc. Root Certificate ( http://www.apple.com/appleca/AppleIncRootCertificate.cer )
    xxd -i ~/Downloads/AppleIncRootCertificate.cer
 */
static const uint8_t _AppleCert[] = {
    0x30, 0x82, 0x04, 0xbb, 0x30, 0x82, 0x03, 0xa3, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x62, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x41, 0x70, 0x70,
    0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x13, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20,
    0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0d, 0x41, 0x70,
    0x70, 0x6c, 0x65, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30,
    0x1e, 0x17, 0x0d, 0x30, 0x36, 0x30, 0x34, 0x32, 0x35, 0x32, 0x31, 0x34,
    0x30, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x32, 0x30, 0x39,
    0x32, 0x31, 0x34, 0x30, 0x33, 0x36, 0x5a, 0x30, 0x62, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x41, 0x70, 0x70,
    0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x13, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20,
    0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0d, 0x41, 0x70,
    0x70, 0x6c, 0x65, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe4, 0x91, 0xa9, 0x09,
    0x1f, 0x91, 0xdb, 0x1e, 0x47, 0x50, 0xeb, 0x05, 0xed, 0x5e, 0x79, 0x84,
    0x2d, 0xeb, 0x36, 0xa2, 0x57, 0x4c, 0x55, 0xec, 0x8b, 0x19, 0x89, 0xde,
    0xf9, 0x4b, 0x6c, 0xf5, 0x07, 0xab, 0x22, 0x30, 0x02, 0xe8, 0x18, 0x3e,
    0xf8, 0x50, 0x09, 0xd3, 0x7f, 0x41, 0xa8, 0x98, 0xf9, 0xd1, 0xca, 0x66,
    0x9c, 0x24, 0x6b, 0x11, 0xd0, 0xa3, 0xbb, 0xe4, 0x1b, 0x2a, 0xc3, 0x1f,
    0x95, 0x9e, 0x7a, 0x0c, 0xa4, 0x47, 0x8b, 0x5b, 0xd4, 0x16, 0x37, 0x33,
    0xcb, 0xc4, 0x0f, 0x4d, 0xce, 0x14, 0x69, 0xd1, 0xc9, 0x19, 0x72, 0xf5,
    0x5d, 0x0e, 0xd5, 0x7f, 0x5f, 0x9b, 0xf2, 0x25, 0x03, 0xba, 0x55, 0x8f,
    0x4d, 0x5d, 0x0d, 0xf1, 0x64, 0x35, 0x23, 0x15, 0x4b, 0x15, 0x59, 0x1d,
    0xb3, 0x94, 0xf7, 0xf6, 0x9c, 0x9e, 0xcf, 0x50, 0xba, 0xc1, 0x58, 0x50,
    0x67, 0x8f, 0x08, 0xb4, 0x20, 0xf7, 0xcb, 0xac, 0x2c, 0x20, 0x6f, 0x70,
    0xb6, 0x3f, 0x01, 0x30, 0x8c, 0xb7, 0x43, 0xcf, 0x0f, 0x9d, 0x3d, 0xf3,
    0x2b, 0x49, 0x28, 0x1a, 0xc8, 0xfe, 0xce, 0xb5, 0xb9, 0x0e, 0xd9, 0x5e,
    0x1c, 0xd6, 0xcb, 0x3d, 0xb5, 0x3a, 0xad, 0xf4, 0x0f, 0x0e, 0x00, 0x92,
    0x0b, 0xb1, 0x21, 0x16, 0x2e, 0x74, 0xd5, 0x3c, 0x0d, 0xdb, 0x62, 0x16,
    0xab, 0xa3, 0x71, 0x92, 0x47, 0x53, 0x55, 0xc1, 0xaf, 0x2f, 0x41, 0xb3,
    0xf8, 0xfb, 0xe3, 0x70, 0xcd, 0xe6, 0xa3, 0x4c, 0x45, 0x7e, 0x1f, 0x4c,
    0x6b, 0x50, 0x96, 0x41, 0x89, 0xc4, 0x74, 0x62, 0x0b, 0x10, 0x83, 0x41,
    0x87, 0x33, 0x8a, 0x81, 0xb1, 0x30, 0x58, 0xec, 0x5a, 0x04, 0x32, 0x8c,
    0x68, 0xb3, 0x8f, 0x1d, 0xde, 0x65, 0x73, 0xff, 0x67, 0x5e, 0x65, 0xbc,
    0x49, 0xd8, 0x76, 0x9f, 0x33, 0x14, 0x65, 0xa1, 0x77, 0x94, 0xc9, 0x2d,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x7a, 0x30, 0x82, 0x01,
    0x76, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
    0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x2b, 0xd0, 0x69,
    0x47, 0x94, 0x76, 0x09, 0xfe, 0xf4, 0x6b, 0x8d, 0x2e, 0x40, 0xa6, 0xf7,
    0x47, 0x4d, 0x7f, 0x08, 0x5e, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
    0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x2b, 0xd0, 0x69, 0x47, 0x94, 0x76,
    0x09, 0xfe, 0xf4, 0x6b, 0x8d, 0x2e, 0x40, 0xa6, 0xf7, 0x47, 0x4d, 0x7f,
    0x08, 0x5e, 0x30, 0x82, 0x01, 0x11, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
    0x82, 0x01, 0x08, 0x30, 0x82, 0x01, 0x04, 0x30, 0x82, 0x01, 0x00, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x05, 0x01, 0x30, 0x81,
    0xf2, 0x30, 0x2a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
    0x01, 0x16, 0x1e, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
    0x77, 0x77, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0x2f, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x63, 0x61, 0x2f, 0x30, 0x81, 0xc3,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x81,
    0xb6, 0x1a, 0x81, 0xb3, 0x52, 0x65, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
    0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x63, 0x65, 0x72,
    0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x62, 0x79, 0x20,
    0x61, 0x6e, 0x79, 0x20, 0x70, 0x61, 0x72, 0x74, 0x79, 0x20, 0x61, 0x73,
    0x73, 0x75, 0x6d, 0x65, 0x73, 0x20, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74,
    0x61, 0x6e, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x74, 0x68, 0x65, 0x6e, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
    0x62, 0x6c, 0x65, 0x20, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64,
    0x20, 0x74, 0x65, 0x72, 0x6d, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x63,
    0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6f, 0x66,
    0x20, 0x75, 0x73, 0x65, 0x2c, 0x20, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
    0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
    0x20, 0x61, 0x6e, 0x64, 0x20, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x70, 0x72, 0x61, 0x63, 0x74,
    0x69, 0x63, 0x65, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
    0x74, 0x73, 0x2e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x5c,
    0x36, 0x99, 0x4c, 0x2d, 0x78, 0xb7, 0xed, 0x8c, 0x9b, 0xdc, 0xf3, 0x77,
    0x9b, 0xf2, 0x76, 0xd2, 0x77, 0x30, 0x4f, 0xc1, 0x1f, 0x85, 0x83, 0x85,
    0x1b, 0x99, 0x3d, 0x47, 0x37, 0xf2, 0xa9, 0x9b, 0x40, 0x8e, 0x2c, 0xd4,
    0xb1, 0x90, 0x12, 0xd8, 0xbe, 0xf4, 0x73, 0x9b, 0xee, 0xd2, 0x64, 0x0f,
    0xcb, 0x79, 0x4f, 0x34, 0xd8, 0xa2, 0x3e, 0xf9, 0x78, 0xff, 0x6b, 0xc8,
    0x07, 0xec, 0x7d, 0x39, 0x83, 0x8b, 0x53, 0x20, 0xd3, 0x38, 0xc4, 0xb1,
    0xbf, 0x9a, 0x4f, 0x0a, 0x6b, 0xff, 0x2b, 0xfc, 0x59, 0xa7, 0x05, 0x09,
    0x7c, 0x17, 0x40, 0x56, 0x11, 0x1e, 0x74, 0xd3, 0xb7, 0x8b, 0x23, 0x3b,
    0x47, 0xa3, 0xd5, 0x6f, 0x24, 0xe2, 0xeb, 0xd1, 0xb7, 0x70, 0xdf, 0x0f,
    0x45, 0xe1, 0x27, 0xca, 0xf1, 0x6d, 0x78, 0xed, 0xe7, 0xb5, 0x17, 0x17,
    0xa8, 0xdc, 0x7e, 0x22, 0x35, 0xca, 0x25, 0xd5, 0xd9, 0x0f, 0xd6, 0x6b,
    0xd4, 0xa2, 0x24, 0x23, 0x11, 0xf7, 0xa1, 0xac, 0x8f, 0x73, 0x81, 0x60,
    0xc6, 0x1b, 0x5b, 0x09, 0x2f, 0x92, 0xb2, 0xf8, 0x44, 0x48, 0xf0, 0x60,
    0x38, 0x9e, 0x15, 0xf5, 0x3d, 0x26, 0x67, 0x20, 0x8a, 0x33, 0x6a, 0xf7,
    0x0d, 0x82, 0xcf, 0xde, 0xeb, 0xa3, 0x2f, 0xf9, 0x53, 0x6a, 0x5b, 0x64,
    0xc0, 0x63, 0x33, 0x77, 0xf7, 0x3a, 0x07, 0x2c, 0x56, 0xeb, 0xda, 0x0f,
    0x21, 0x0e, 0xda, 0xba, 0x73, 0x19, 0x4f, 0xb5, 0xd9, 0x36, 0x7f, 0xc1,
    0x87, 0x55, 0xd9, 0xa7, 0x99, 0xb9, 0x32, 0x42, 0xfb, 0xd8, 0xd5, 0x71,
    0x9e, 0x7e, 0xa1, 0x52, 0xb7, 0x1b, 0xbd, 0x93, 0x42, 0x24, 0x12, 0x2a,
    0xc7, 0x0f, 0x1d, 0xb6, 0x4d, 0x9c, 0x5e, 0x63, 0xc8, 0x4b, 0x80, 0x17,
    0x50, 0xaa, 0x8a, 0xd5, 0xda, 0xe4, 0xfc, 0xd0, 0x09, 0x07, 0x37, 0xb0,
    0x75, 0x75, 0x21
};


// ASN.1 values for In-App Purchase values
#define INAPP_ATTR_START	1700
#define INAPP_QUANTITY		1701
#define INAPP_PRODID		1702
#define INAPP_TRANSID		1703
#define INAPP_PURCHDATE		1704
#define INAPP_ORIGTRANSID	1705
#define INAPP_ORIGPURCHDATE	1706
#define INAPP_ATTR_END		1707
#define INAPP_SUBEXP_DATE   1708
#define INAPP_WEBORDER      1711
#define INAPP_CANCEL_DATE   1712

static inline int _get_asn1_int(const uint8_t **pp, long maxlen) {

    assert(pp && *pp);

    long len = 0;
    int type = 0, xclass = 0;
    const uint8_t *p = *pp;

    ASN1_get_object(&p, &len, &type, &xclass, maxlen);

    int v = 0;
    if (type == V_ASN1_INTEGER && (p+len)<=(*pp+maxlen)) {
        for (; len>0; len--) {
            v = (v << 8) + *p;
            p ++;
        }
        *pp = p;
    }
    return v;
}

NSArray *parseInAppPurchasesData(NSData *inappData) {
	int type = 0;
	int xclass = 0;
	long length = 0;

    NSDateFormatter *rfc3339DateFormatter = [[NSDateFormatter alloc] init];
    NSLocale *enUSPOSIXLocale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    
    [rfc3339DateFormatter setLocale:enUSPOSIXLocale];
    [rfc3339DateFormatter setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"];
    [rfc3339DateFormatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];

	NSUInteger dataLenght = [inappData length];
	const uint8_t *p = [inappData bytes];
    
	const uint8_t *end = p + dataLenght;
    
	NSMutableArray *resultArray = [NSMutableArray array];
    
	while (p < end) {
		ASN1_get_object(&p, &length, &type, &xclass, end - p);
        
		const uint8_t *set_end = p + length;
        
		if(type != V_ASN1_SET) {
			break;
		}
        
		NSMutableDictionary *item = [[NSMutableDictionary alloc] initWithCapacity:6];
        
		while (p < set_end) {
			ASN1_get_object(&p, &length, &type, &xclass, set_end - p);
			if (type != V_ASN1_SEQUENCE) {
				break;
            }
            
			const uint8_t *seq_end = p + length;
            
			int attr_type = _get_asn1_int(&p, seq_end - p);
			__unused int attr_version = _get_asn1_int(&p, seq_end - p);
            
			// Only parse attributes we're interested in
			if ((attr_type > INAPP_ATTR_START && attr_type < INAPP_ATTR_END) || attr_type == INAPP_SUBEXP_DATE || attr_type == INAPP_WEBORDER || attr_type == INAPP_CANCEL_DATE) {
				NSString *key = nil;
                
				ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
				if (type == V_ASN1_OCTET_STRING) {
					//NSData *data = [NSData dataWithBytes:p length:(NSUInteger)length];
                    
					// Integers
					if (attr_type == INAPP_QUANTITY || attr_type == INAPP_WEBORDER) {
                            
                        const uint8_t *num_p = p;
                        NSUInteger quantity = _get_asn1_int(&num_p, seq_end-num_p);
							NSNumber *num = [[NSNumber alloc] initWithUnsignedInteger:quantity];
                            if (attr_type == INAPP_QUANTITY) {
                                [item setObject:num forKey:kReceiptInAppQuantity];
                            } else if (attr_type == INAPP_WEBORDER) {
                                [item setObject:num forKey:kReceiptInAppWebOrderLineItemID];
                            }
						}
                    
					// Strings
					if (attr_type == INAPP_PRODID ||
                        attr_type == INAPP_TRANSID ||
                        attr_type == INAPP_ORIGTRANSID ||
                        attr_type == INAPP_PURCHDATE ||
                        attr_type == INAPP_ORIGPURCHDATE ||
                        attr_type == INAPP_SUBEXP_DATE ||
                        attr_type == INAPP_CANCEL_DATE) {
                        
						int str_type = 0;
						long str_length = 0;
						const uint8_t *str_p = p;
						ASN1_get_object(&str_p, &str_length, &str_type, &xclass, seq_end - str_p);
						if (str_type == V_ASN1_UTF8STRING) {
							switch (attr_type) {
								case INAPP_PRODID:
									key = kReceiptInAppProductIdentifier;
									break;
								case INAPP_TRANSID:
									key = kReceiptInAppTransactionIdentifier;
									break;
								case INAPP_ORIGTRANSID:
									key = kReceiptInAppOriginalTransactionIdentifier;
									break;
							}
                            
							if (key) {
								NSString *string = [[NSString alloc] initWithBytes:str_p
																			length:(NSUInteger)str_length
																		  encoding:NSUTF8StringEncoding];
								[item setObject:string forKey:key];
							}
						}
						if (str_type == V_ASN1_IA5STRING) {
							switch (attr_type) {
								case INAPP_PURCHDATE:
									key = kReceiptInAppPurchaseDate;
									break;
								case INAPP_ORIGPURCHDATE:
									key = kReceiptInAppOriginalPurchaseDate;
									break;
								case INAPP_SUBEXP_DATE:
									key = kReceiptInAppSubscriptionExpirationDate;
									break;
								case INAPP_CANCEL_DATE:
									key = kReceiptInAppCancellationDate;
									break;
							}
                            
							if (key && str_length>0) {
								NSString *string = [[NSString alloc] initWithBytes:str_p
																			length:(NSUInteger)str_length
																		  encoding:NSASCIIStringEncoding];
                                NSDate *date = [rfc3339DateFormatter dateFromString:string];
								[item setObject:(date ? date : string) forKey:key];
							}
						}
					}
				}
                
				p += length;
			}
            
			// Skip any remaining fields in this SEQUENCE
			while (p < seq_end) {
				ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
				p += length;
			}
		}
        
		// Skip any remaining fields in this SET
		while (p < set_end) {
			ASN1_get_object(&p, &length, &type, &xclass, set_end - p);
			p += length;
		}
        
		[resultArray addObject:item];
	}
    
	return resultArray;
}

// ASN.1 values for the App Store receipt
#define ATTR_START 1
#define BUNDLE_ID 2
#define VERSION 3
#define OPAQUE_VALUE 4
#define HASH 5
#define ATTR_END 6
#define INAPP_PURCHASE 17
#define ORIG_VERSION 19
#define EXPIRE_DATE 21

NSDictionary *dictionaryWithAppStoreReceipt(NSString *receiptPath) {

	ERR_load_PKCS7_strings();
	ERR_load_X509_strings();
	OpenSSL_add_all_digests();
    
	// Expected input is a PKCS7 container with signed data containing
	// an ASN.1 SET of SEQUENCE structures. Each SEQUENCE contains
	// two INTEGERS and an OCTET STRING.
    
	const char * path = [[receiptPath stringByStandardizingPath] fileSystemRepresentation];
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		ReceiptLog(@"Could not open receipt at %@.", [receiptPath stringByStandardizingPath]);
		return nil;
    }
    
	PKCS7 *p7 = d2i_PKCS7_fp(fp, NULL);
	fclose(fp);
    
	// Check if the receipt file was invalid (otherwise we go crashing and burning)
	if (p7 == NULL) {
		ReceiptLog(@"Could not create PKCS7 container.");
		return nil;
	}
    
	if (!PKCS7_type_is_signed(p7)) {
		PKCS7_free(p7);
		return nil;
	}
    
	if (!PKCS7_type_is_data(p7->d.sign->contents)) {
		PKCS7_free(p7);
		return nil;
	}
    
	int verifyReturnValue = 0;
	X509_STORE *store = X509_STORE_new();
	if (store) {
		const uint8_t *data = _AppleCert;
		X509 *appleCA = d2i_X509(NULL, &data, sizeof(_AppleCert)/sizeof(_AppleCert[0]));
		if (appleCA) {
			BIO *payload = BIO_new(BIO_s_mem());
			X509_STORE_add_cert(store, appleCA);
            
			if (payload) {
				verifyReturnValue = PKCS7_verify(p7,NULL,store,NULL,payload,0);
				BIO_free(payload);
			}
            
			X509_free(appleCA);
		}
        
		X509_STORE_free(store);
	}
    
	EVP_cleanup();
    
	if (verifyReturnValue != 1) {
		PKCS7_free(p7);
		return nil;
	}
    
	ASN1_OCTET_STRING *octets = p7->d.sign->contents->d.data;
	const uint8_t *p = octets->data;
	const uint8_t *end = p + octets->length;
    
	int type = 0;
	int xclass = 0;
	long length = 0;
    
	ASN1_get_object(&p, &length, &type, &xclass, end - p);
	if (type != V_ASN1_SET) {
		PKCS7_free(p7);
		return nil;
	}
    
	NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
	while (p < end) {
		ASN1_get_object(&p, &length, &type, &xclass, end - p);
		if (type != V_ASN1_SEQUENCE) {
			break;
        }
        
		const uint8_t *seq_end = p + length;
        
		int attr_type = _get_asn1_int(&p, seq_end - p);
		__unused int attr_version = _get_asn1_int(&p, seq_end - p);
        
		// Only parse attributes we're interested in
		if ((attr_type > ATTR_START && attr_type < ATTR_END) || attr_type == INAPP_PURCHASE || attr_type == ORIG_VERSION || attr_type == EXPIRE_DATE) {
			NSString *key = nil;
            
			ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
			if (type == V_ASN1_OCTET_STRING) {
                NSData *data = [NSData dataWithBytes:p length:(NSUInteger)length];
                
				// Bytes
				if (attr_type == BUNDLE_ID || attr_type == OPAQUE_VALUE || attr_type == HASH) {
					switch (attr_type) {
						case BUNDLE_ID:
							// This is included for hash generation
							key = kReceiptBundleIdentifierData;
							break;
						case OPAQUE_VALUE:
							key = kReceiptOpaqueValue;
							break;
						case HASH:
							key = kReceiptHash;
							break;
					}
					if (key) {
                        [info setObject:data forKey:key];
                    }
				}
                
				// Strings
				if (attr_type == BUNDLE_ID || attr_type == VERSION || attr_type == ORIG_VERSION || attr_type == EXPIRE_DATE) {
					int str_type = 0;
					long str_length = 0;
					const uint8_t *str_p = p;
                    
                    switch (attr_type) {
                        case BUNDLE_ID:
                            key = kReceiptBundleIdentifier;
                            break;
                        case VERSION:
                            key = kReceiptVersion;
                            break;
                        case ORIG_VERSION:
                            key = kReceiptOriginalVersion;
                            break;
                        case EXPIRE_DATE:
                            key = kReceiptExpirationDate;
                            break;
                    }

					ASN1_get_object(&str_p, &str_length, &str_type, &xclass, seq_end - str_p);
					if (key && str_length>0) {
                        if (str_type == V_ASN1_UTF8STRING) {
                            NSString *string = [[NSString alloc] initWithBytes:str_p
																		length:(NSUInteger)str_length
                                                                      encoding:NSUTF8StringEncoding];
                            [info setObject:string forKey:key];
                        } else if (str_type == V_ASN1_IA5STRING) {
                            NSDateFormatter *rfc3339DateFormatter = [[NSDateFormatter alloc] init];
                            NSLocale *enUSPOSIXLocale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
                            
                            [rfc3339DateFormatter setLocale:enUSPOSIXLocale];
                            [rfc3339DateFormatter setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"];
                            [rfc3339DateFormatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
                            
                            NSString *string = [[NSString alloc] initWithBytes:str_p
                                                                        length:(NSUInteger)str_length
                                                                      encoding:NSASCIIStringEncoding];
                            NSDate *date = [rfc3339DateFormatter dateFromString:string];
                            [info setObject:(date ? date : string) forKey:key];
                        }
                    }
				}
                
				// In-App purchases
				if (attr_type == INAPP_PURCHASE) {
					NSArray *inApp = parseInAppPurchasesData(data);
                    NSArray *current = info[kReceiptInApp];
                    if (current) {
                        info[kReceiptInApp] = [current arrayByAddingObjectsFromArray:inApp];
                    } else {
                        [info setObject:inApp forKey:kReceiptInApp];
                    }
				}
			}
			p += length;
		}
        
		// Skip any remaining fields in this SEQUENCE
		while (p < seq_end) {
			ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
			p += length;
		}
	}
    
	PKCS7_free(p7);
    
	return info;
}


NSArray *obtainInAppPurchases(NSString *receiptPath) {
	// According to the documentation, we need to validate the receipt first.
	// If the receipt is not valid, no In-App purchase is valid.
	// This performs a "quick" validation. Please use validateReceiptAtPath to perform a full validation.
    
	NSDictionary *receipt = dictionaryWithAppStoreReceipt(receiptPath);
	if (!receipt) {
		return nil;
    }
    
	NSArray *purchases = [receipt objectForKey:kReceiptInApp];
	if(!purchases || ![purchases isKindOfClass:[NSArray class]]) {
		return nil;
    }
    
	return purchases;
}

extern const NSString * global_bundleVersion;
extern const NSString * global_bundleIdentifier;

// in your project define those two somewhere as such:
// const NSString * global_bundleVersion = @"1.0.2";
// const NSString * global_bundleIdentifier = @"com.example.SampleApp";

BOOL verifyReceiptAtPath(NSString *receiptPath) {
	// it turns out, it's a bad idea, to use these two NSBundle methods in your app:
	//
	// bundleVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
	// bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
	//
	// http://www.craftymind.com/2011/01/06/mac-app-store-hacked-how-developers-can-better-protect-themselves/
	//
	// so use hard coded values instead (probably even somehow obfuscated)
    
	NSString *bundleVersion = (NSString*)global_bundleVersion;
	NSString *bundleIdentifier = (NSString*)global_bundleIdentifier;

	// avoid making stupid mistakes --> check again
	NSCAssert([bundleVersion isEqualToString:[[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]],
              @"whoops! check the hard-coded CFBundleShortVersionString!");
	NSCAssert([bundleIdentifier isEqualToString:[[NSBundle mainBundle] bundleIdentifier]],
              @"whoops! check the hard-coded bundle identifier!");
	NSDictionary *receipt = dictionaryWithAppStoreReceipt(receiptPath);
    
	if (!receipt) {
		return NO;
    }
    
    // See if we are past any expiration date
    NSDate *expired = receipt[kReceiptExpirationDate];
    if ([expired timeIntervalSinceNow] < 0.0) {
        return NO;
    }

    unsigned char uuidBytes[16];
    NSUUID *vendorUUID = [[UIDevice currentDevice] identifierForVendor];
    [vendorUUID getUUIDBytes:uuidBytes];
    
	NSMutableData *input = [NSMutableData data];
	[input appendBytes:uuidBytes length:sizeof(uuidBytes)];
	[input appendData:[receipt objectForKey:kReceiptOpaqueValue]];
	[input appendData:[receipt objectForKey:kReceiptBundleIdentifierData]];
    
	NSMutableData *hash = [NSMutableData dataWithLength:SHA_DIGEST_LENGTH];
	SHA1([input bytes], [input length], [hash mutableBytes]);
    
	if ([bundleIdentifier isEqualToString:receipt[kReceiptBundleIdentifier]] &&
        [bundleVersion isEqualToString:receipt[kReceiptVersion]] &&
        [hash isEqualToData:receipt[kReceiptHash]]) {
		return YES;
	}
    
	return NO;
}
