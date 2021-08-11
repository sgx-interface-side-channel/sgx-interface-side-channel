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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "operations.h"
#include <iostream>
#include <fstream>
#include <dirent.h>
#include <cstring>
#include <cwchar>
#include <fstream>
#include "sample_libcrypto.h"

//int encrypt_file(char* pcapdir);
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
        {
                SGX_ERROR_UNEXPECTED,
                "Unexpected error occurred.",
                NULL
        },
        {
                SGX_ERROR_INVALID_PARAMETER,
                "Invalid parameter.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_MEMORY,
                "Out of memory.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_LOST,
                "Power transition occurred.",
                "Please refer to the sample \"PowerTransition\" for details."
        },
        {
                SGX_ERROR_INVALID_ENCLAVE,
                "Invalid enclave image.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ENCLAVE_ID,
                "Invalid enclave identification.",
                NULL
        },
        {
                SGX_ERROR_INVALID_SIGNATURE,
                "Invalid enclave signature.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_EPC,
                "Out of EPC memory.",
                NULL
        },
        {
                SGX_ERROR_NO_DEVICE,
                "Invalid SGX device.",
                "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
        },
        {
                SGX_ERROR_MEMORY_MAP_CONFLICT,
                "Memory map conflicted.",
                NULL
        },
        {
                SGX_ERROR_INVALID_METADATA,
                "Invalid enclave metadata.",
                NULL
        },
        {
                SGX_ERROR_DEVICE_BUSY,
                "SGX device was busy.",
                NULL
        },
        {
                SGX_ERROR_INVALID_VERSION,
                "Enclave version was invalid.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ATTRIBUTE,
                "Enclave was not authorized.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_FILE_ACCESS,
                "Can't open enclave file.",
                NULL
        },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

size_t GetFileSize(char* filename)
{
    size_t size = 0;
    FILE  *fp = fopen(filename, "rb");

    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fclose(fp);
    }

    return size;
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    /* -------------------Editing From Here------------------------- */
    char dir[] = "../Web/";
//    encrypt_file(dir);

    sgx_status_t status = SGX_SUCCESS;

    struct dirent *ptr = nullptr;
    DIR *dp = nullptr;
    dp = opendir(dir);
    if (dp != nullptr) {
        while ((ptr = readdir(dp)) != nullptr) {
            if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
                continue;
            } else {
                // 计算文件大小
//                printf ("%s\n", ptr->d_name);
                /*------------------Encryption----------------------------*/
                int ret;
                uint8_t en_mac[16];
                /* Encrypt a given file */
                const uint8_t data_key[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};
                uint8_t aes_gcm_iv[12] = {0};
                char buf1[100], buf2[100], buf3[100];
                sprintf(buf1, "../Web/%s",ptr->d_name);
                sprintf(buf2, "../WebEnc/%s_en", ptr->d_name);
                sprintf(buf3, "../WebEnc/%s_en_mac", ptr->d_name);
                FILE *ifp = fopen(buf1, "rb");
                if(ifp==nullptr){
                    printf("\nFile %s not exist.\n",buf1);
                    return 1;
                }
                FILE *ofp_ctext = fopen(buf2, "wb");
                if(ofp_ctext==nullptr){
                    printf("\nCan not open or create file %s.\n",buf2);
                    return 1;
                }
                FILE *ofp_mac = fopen(buf3, "wb");
                if(ofp_mac==nullptr){
                    printf("\nCan not open or create file %s.\n",buf3);
                    return 1;
                }
                size_t lSize;
                lSize=GetFileSize(buf1);
//                if (lSize>500000||lSize==0) continue;
                if (lSize==0) continue;
//                if (lSize==0) continue;
                // Use AES-GCM provided in sample_crypto.h
                uint8_t* cleartext;
                uint8_t* cyphertext;
                cleartext =  (uint8_t*) malloc (sizeof(uint8_t)*lSize);
                cyphertext = (uint8_t*) malloc (sizeof(uint8_t)*lSize);
//                printf("lSize:%d\n",lSize);
                fread(cleartext, 1, lSize, ifp);

                ret = sample_rijndael128GCM_encrypt(
                        &data_key,
                        cleartext,
                        lSize,
                        cyphertext, // Output
                        &aes_gcm_iv[0],
                        12,
                        NULL,
                        0,
                        &en_mac); // Output

                fwrite(cyphertext, 1, lSize, ofp_ctext);
                fwrite(en_mac, 1, SAMPLE_AESGCM_MAC_SIZE, ofp_mac);

                fclose(ifp);
                fclose(ofp_ctext);
                fclose(ofp_mac);
//                printf("encrypt_file Completed\n");

                /*------------------Enclave Processing----------------------------*/
                double tic, toc;
                double tTotal = 0;
                size_t oSize;
                uint8_t* encProcessedtext;
                /* Allocate space for processed data */
                encProcessedtext = (uint8_t*) malloc (10*sizeof(uint8_t)*lSize);
//                printf("lSize:%d\n",lSize);
                memset(encProcessedtext,0,2*sizeof(uint8_t)*lSize);
                // 开始计时
                tic = stime();
                size_t matched = 0;
//                printf("A\n");
                enclave_ids(global_eid,&status,cleartext,lSize,en_mac,&oSize,encProcessedtext,&matched);
                // 结束计时
                toc = stime();
                tTotal += (toc - tic);
                if(matched) {
                    printf("IDS(Legal):%s:Time:%f\n", ptr->d_name, tTotal);
                }else{
                    printf("IDS(Illegal):%s:Time:%f\n", ptr->d_name, tTotal);
                }

                tic = stime();
                // 传入密文和mac，在enclave中进行分析，并输出处理后数据的密文
                // ecall的第一个参数是eid，第二个参数是status，后面的才是EDL中自定义的
                enclave_compression(global_eid,&status,cyphertext,lSize,en_mac,&oSize,encProcessedtext);
                toc = stime();
                tTotal += (toc - tic);
                printf("Compression:%s:Time:%f:InputSize:%d:OutputSize:%d\n", ptr->d_name,tTotal,lSize,oSize);
                free(cleartext);
                free(cyphertext);
            }
        }
    }
    /* -------------------Editing Done----------------------------- */

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

//    printf("Info: NFVEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}
