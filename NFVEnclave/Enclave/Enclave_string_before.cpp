/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>
//#include <stdlib.h>
#include <vector>
#include <regex>
//#include "sample_libcrypto.h"
// Needed for definition of remote attestation messages.
//#include "remote_attestation_result.h"
//#include "isv_enclave_u.h"
// Needed to call untrusted key exchange include APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
//#include "network_ra.h"
// Needed to create enclave and do ecall.
#include "sgx_urts.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"
#include "ahocorasick.h"
//#include "service_provider.h"
//#include "sample_messages.h"
//#include "sample_libcrypto.h"

// #include "enclave_utilities.h"
//#include "svm.h"
//#include "fann.h"
//#include "keccak.h"
using namespace std;
uint8_t data_key[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};
uint8_t aes_gcm_iv[12] = {0};
int new_length = 0;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/* Define a call-back function of type MF_REPLACE_CALBACK_f */
void listener (AC_TEXT_t *text, void *user)
{
    int ret = 0;
//    printf("Length:%d",(int)text->length);
    int i = 1;
//    int invariant = 0;
    while (i<(int)text->length){
//        invariant = invariant + 1;
        i = i * 2;
    }
//    new_length = (int)text->length;
    new_length = i;
}

void split(const string &s, vector<string>& tokens, const string& delimiters)
{
    size_t lastPos = s.find_first_not_of(delimiters, 0);
    size_t pos = s.find_first_of(delimiters, lastPos);
    while (string::npos != pos || string::npos != lastPos) {
        tokens.push_back(s.substr(lastPos, pos - lastPos));//use emplace_back after C++11
        lastPos = s.find_first_not_of(delimiters, pos);
        pos = s.find_first_of(delimiters, lastPos);
    }
//    std::string text = "Quick brown fox.";
}

void replaceAll( string &s, const string &search, const string &replace ) {

    for( size_t pos = 0; ; pos += replace.length() ) {
        // Locate the substring to replace
        pos = s.find( search, pos );
        if( pos == string::npos ) break;
        // Replace by erasing and inserting
        s.erase( pos, search.length() );
        s.insert( pos, replace );
    }
}

int get_padding_size(int count){
    int pad = 1;
    while(count > pad){
        pad = pad * 2;
    }
    return pad;
}

sgx_status_t enclave_process_badword(uint8_t* cyphertext, size_t lSize,
                                     uint8_t* en_mac, size_t* oSize,
                                     uint8_t* encProcessedtext)
{
    sgx_status_t ret = SGX_SUCCESS;
    ret = sgx_rijndael128GCM_decrypt(
            (const sgx_ec_key_128bit_t*) data_key, //(const sgx_ec_key_128bit_t*) g_secret_DO,
            cyphertext,
            lSize,
            encProcessedtext,
            aes_gcm_iv,
            12,
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t*) en_mac);

    // encProcesslist: char * encProcessedtext
    string str((char*)encProcessedtext);
    string rules = "locale|padding|html|css|com|cdn|google";
    vector<string> patterns;
    split(rules,patterns,"|");

    for (vector<string>::iterator it=patterns.begin();it!=patterns.end();++it){
        replaceAll(str,*it,"");
    }
    new_length = get_padding_size(str.size());
    str.insert(str.end(), new_length - str.size(), ' ');
    *oSize=new_length;
    strncpy((char *)encProcessedtext, str.c_str(), *oSize);

    uint8_t en_mac_new[16];

    ret = sgx_rijndael128GCM_encrypt(
            (const sgx_ec_key_128bit_t*) data_key,
            encProcessedtext,
            *oSize,
            encProcessedtext, // Output
            aes_gcm_iv,
            12,
            NULL,
            0,
            &en_mac_new); // Output
    return ret;
//    ac_trie_release (trie);
}