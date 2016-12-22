//
//  TwitterOAuth.cpp
//  twitter-oauth-commandline
//
//  Created by leico on 2016/12/22.
//  Copyright © 2016年 leico. All rights reserved.
//

#include "TwitterOAuth.hpp"

const std :: string TwitterOAuth :: SIGNATURE_METHOD("HMAC-SHA1");
const std :: string TwitterOAuth :: OAUTH_VERSION   ("1.0");

const int TwitterOAuth :: NONCE_LETTER_COUNT = 32;

size_t (*const TwitterOAuth :: NULL_RESPONSEFUNC)(char*, size_t, size_t, void*) = 0;
int    (*const TwitterOAuth :: NULL_PROGRESSFUNC)(void*, curl_off_t, curl_off_t, curl_off_t, curl_off_t) = 0;
