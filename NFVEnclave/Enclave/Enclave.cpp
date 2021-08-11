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
//#include <stdio.h> /* vsnprintf */
#include <string>
//#include <stdlib.h>
#include <vector>
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



#define PATTERN(p,r)    {{p,strlen(p)},{r,strlen(r)},{{0},AC_PATTID_TYPE_DEFAULT}}
#define CHUNK(c)        {c,strlen(c)}

void generate_patterns(AC_TRIE_t * trie_l){
    char badwords[] = "carpet muncher|cawk|chink|cipa|cl1t|clit|clitoris|coksucka|coon|cox|crap|beastial|clits|cnut|cock|cock-sucker|cockface|cockhead|cockmuncher|cocks|cocksucks|cocksuka|cocksukka|cok|cokmuncher|cum|cummer|cumming|cums|cumshot|cunilingus|cunillingus|cunnilingus|cunt|cuntlicker|cuntlick|cocksuck|cocksucked|cocksucker|cocksucking|cockmunch|blowjob|bitchin|bitcher|bitch|bestial|asshole||cuntlicking|cunts|cyalis|cyberfuc|cyberfuck|cyberfucked|cyberfucker|cyberfuckers|cyberfucking|d1ck|damn|dick|dickhead|dildo|dildos|dink|dinks|dirsa|dlck|dog-fucker|doggin|dogging|donkeyribber|doosh|duche|dyke|ejaculate|ejaculated|ejaculates|ejaculating|ejaculatings|ejaculation|ejakulate|f u c k|f u c k e r|f4nny|fag|fagging|faggitt|faggot|faggs|fagot|fagots|fags|fanny|fannyflaps|fannyfucker|fanyy|fatass|fcuk|fcuker|fcuking|feck|fecker|felching|fellate|fellatio|fingerfuck|fingerfucked|fingerfucker|fingerfuckers|fingerfucking|fingerfucks|fistfuck|fistfucked|fistfucker|fistfuckers|fistfucking|fistfuckings|fistfucks|flange|fook|fooker|fuck|fucka|fucked|fucker|fuckers|fuckhead|fuckheads|fuckin|fucking|fuckings|fuckingshitmotherfucker|fuckme|fucks|fuckwhit|fuckwit|fudge packer|fudgepacker|fuk|fuker|fukker|fukkin|fuks|fukwhit|fukwit|fux|fux0r|f_u_c_k|gangbang|gangbanged|gangbangs|gaylord|gaysex|goatse|God|god-dam|god-damned|goddamn|goddamned|hardcoresex|hell|heshe|hoar|hoare|hoer|homo|hore|horniest|horny|hotsex|jack-off|jackoff|jap|jerk-off|jism|jiz|jizm|jizz|kawk|knob|knobead|knobed|knobend|knobhead|knobjocky|knobjokey|kock|kondum|kondums|kum|kummer|kumming|kums|kunilingus|l3itch|labia|lust|lusting|m0f0|m0fo|m45terbate|ma5terb8|ma5terbate|masochist|master-bate|masterb8|masterbat*|masterbat3|masterbate|masterbation|masterbations|masturbate|mo-fo|mof0|mofo|mothafuck|mothafucka|mothafuckas|mothafuckaz|mothafucked|mothafucker|mothafuckers|mothafuckin|mothafucking|mothafuckings|mothafucks|mother fucker|motherfuck|motherfucked|motherfucker|motherfuckers|motherfuckin|motherfucking|motherfuckings|motherfuckka|motherfucks|muff|mutha|muthafecker|muthafuckker|muther|mutherfucker|n1gga|n1gger|nazi|nigg3r|nigg4h|nigga|niggah|niggas|niggaz|nigger|niggers|nob|nob jokey|nobhead|nobjocky|nobjokey|numbnuts|nutsack|orgasim|orgasims|orgasm|orgasms|p0rn|pawn|pecker|penis|penisfucker|phonesex|phuck|phuk|phuked|phuking|phukked|phukking|phuks|phuq|pigfucker|pimpis|piss|pissed|pisser|pissers|pisses|pissflaps|pissin|pissing|pissoff|poop|porn|porno|pornography|pornos|prick|pricks|pron|pube|pusse|pussi|pussies|pussy|pussys|rectum|retard|rimjaw|rimming|s hit|s.o.b.|sadist|schlong|screwing|scroat|scrote|scrotum|semen|sex|sh!t|sh1t|shag|shagger|shaggin|shagging|shemale|shit|shitdick|shite|shited|shitey|shitfuck|shitfull|shithead|shiting|shitings|shits|shitted|shitter|shitters|shitting|shittings|shitty|skank|slut|sluts|smegma|smut|snatch|son-of-a-bitch|spac|spunk|s_h_i_t|t1tt1e5|t1tties|teets|teez|testical|testicle|tit|titfuck|tits|titt|tittie5|tittiefucker|titties|tittyfuck|tittywank|titwank|tosser|turd|tw4t|twat|twathead|twatty|twunt|twunter|v14gra|v1gra|vagina|viagra|vulva|w00se|wang|wank|wanker|wanky|whoar|whore|willies|willy|xrated|xxx|locale|padding|html|css|com|cdn|google|com|cdn|google|locale|padding|html|arrse|arse|ass|ass-fucker|assfucker|assfukka|assholes|asswhole|a_s_s|b!tch|b00bs|b17ch|b1tch|ballbag|balls|ballsack|bastard|beastiality|bellend|bestiality|bitch|biatch|bitchers|bitches|bitching|bloody|blow job|blowjobs|boiolas|bollock|bollok|boner|boob|boobs|booobs|boooobs|booooobs|booooooobs|breasts|buceta|bugger|bum|bunny fucker|butt|butthole|buttmuch|buttplug|c0ck|c0cksucker";
//    char badwords[] = "";
    const char * delim = "|";
    char *p;
//    std::map<int, std::string> badwords_map;
    vector<char*> badwords_vec;
    /* 将badwords读入到字典中 */
    p = strtok(badwords, delim);
    int count = 1;
    while(p){
//        printf("%s\n",p);
        badwords_vec.push_back(p);
        count++;
        p = strtok(NULL, delim);
    }
    int loop_invarient = 1;
    while (count>loop_invarient){
        loop_invarient = loop_invarient *2;
    }
    int additional = loop_invarient - count;
    vector<char*> badwords_vec_fake;
    while(additional){
//        printf("%s\n",p);
        char *q = "locale";
        badwords_vec_fake.push_back(q);
        additional--;
        q = strtok(NULL, delim);
    }
    if (p)
    {
        AC_PATTERN_t patterns[badwords_vec.size()];
    }else{
        AC_PATTERN_t patterns_fake[badwords_vec.size()];
    }
    count = 1;
    for(vector<char*>::iterator iter = badwords_vec.begin(); iter != badwords_vec.end(); iter++)
    {
        count++;
        AC_PATTERN_t pattern = PATTERN(*iter,"");
        ac_trie_add(trie_l, &pattern , 0);
    }
    loop_invarient = 1;
    while (count>loop_invarient){
        loop_invarient = loop_invarient *2;
    }
    additional = loop_invarient - count;
}


/* Define a call-back function of type MF_REPLACE_CALBACK_f */
void listener (AC_TEXT_t *text, void* len)
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
    *(int*)len = i;
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
//    str = std::regex_replace(str, std::regex("def"), "");
}

uint8_t data_key[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};
uint8_t aes_gcm_iv[12] = {0};
int new_length = 1;

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

    AC_TEXT_t input_chunk = CHUNK((const char*)encProcessedtext);

    AC_TRIE_t *trie;

    /* Get a new trie */
    trie = ac_trie_create();

    /* Generate and add patterns into the trie */
    generate_patterns(trie);
    /* Finalize the trie */
    ac_trie_finalize (trie);
    /* Replace */
    multifast_replace (trie, &input_chunk, MF_REPLACE_MODE_NORMAL, listener, &new_length);
    /* Flush the buffer */
    multifast_rep_flush (trie, 0);
    *oSize=new_length;

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


int matching(char* webpage, char* matchString){
    int foundMatch = 0;
    char *p1, *p2, *p3;
    int i=0,j=0,flag=0;
    int page_len = strlen(webpage);
    int match_len = strlen(matchString);

    p1 = webpage;
    p2 = matchString;

    int iter_count1 = 0;

    // 从第一位开始匹配matchString的第一位
    for(i = 0; i<page_len; i++)
    {
        // 如果某一位和matchString的第一位匹配，则开始找下面的位
        if(*p1 == *p2)
        {
            p3 = p1;
            int iter_count2 = 0;
            for(j = 0; j<match_len; j++)
            {
                iter_count2++;
                if(*p3 == *p2)
                {
                    p3++;
                    p2++;
                }
                else{
                    p3--;
                    p3++;
                    break;
                }
            }
            /*---------------------constant loop start------------------*/

            int pad = get_padding_size(iter_count2)-iter_count2;
            // 添加循环次数
            for(int p=0;p<pad;p++){
                iter_count2=iter_count2;
                if(*p3 == *p2)
                {
                    p3--;
                    p3++;
                }
                else{
                    p3--;
                    p3++;
                }
            }

            /*---------------------constant loop stop------------------*/
            p2 = matchString;
            if(j == strlen(matchString))
            {
                flag = 1;
            }else{
                flag = flag;
            }
        }
        /*-------------------- branch elimination start----------------*/
        p3 = p3;
        int iter_count2 = 0;
        for(j = 0; j<match_len; j++)
        {
            iter_count2++;
            if(*p3 == *p2)
            {
                p3--;
                p3++;
            }
            else{
                p3--;
                p3++;
                break;
            }
        }
        // 添加循环次数
        for(int p=0;p<get_padding_size(iter_count2)-iter_count2;p++){
            iter_count2=iter_count2;
            if(*p3 == *p2)
            {
                p3--;
                p3++;
            }
            else{
                p3--;
                p3++;
            }
        }
        p2 = p2;
        if(j == strlen(matchString))
        {
            flag = flag;
//                return 1;
        }else{
            flag = flag;
        }
        /*-------------------- branch elimination stop----------------*/
        p1++;
        iter_count1++;
    }

    /*---------------------constant loop start------------------*/
    int pad_1 = get_padding_size(iter_count1)-iter_count1;
    for (int k = 0; k < pad_1; ++k) {
        // 如果某一位和matchString的第一位匹配，则开始找下面的位
        if(*p1 == *p2)
        {
            p1=p1;
            iter_count1=iter_count1;
            p3 = p3;
            int iter_count2 = 0;
            for(j = 0; j<match_len; j++)
            {
                iter_count2++;
                if(*p3 == *p2)
                {
                    p3--;
                    p3++;
                }
                else{
                    p3--;
                    p3++;
                    break;
                }
            }
            int pad_2 = get_padding_size(iter_count2)-iter_count2;
            // 添加循环次数
            for(int p=0;p<pad_2;p++){
                iter_count2=iter_count2;
                if(*p3 == *p2)
                {
                    p3--;
                    p3++;
                }
                else{
                    p3--;
                    p3++;
                }
            }
            p2 = p2;
            if(j == strlen(matchString))
            {
                flag = flag;
//                return 1;
            }else{
                flag = flag;
            }
        }
        /*-------------------------------- copyed to here------------------*/
        p3 = p3;
        int iter_count2 = 0;
        for(j = 0; j<match_len; j++)
        {
            iter_count2++;
            if(*p3 == *p2)
            {
                p3--;
                p3++;
            }
            else{
                p3--;
                p3++;
                break;
            }
        }
        // 添加循环次数
        for(int p=0;p<get_padding_size(iter_count2)-iter_count2;p++){
            iter_count2=iter_count2;
            if(*p3 == *p2)
            {
                p3--;
                p3++;
            }
            else{
                p3--;
                p3++;
            }
        }
        p2 = p2;
        if(j == strlen(matchString))
        {
            flag = flag;
//                return 1;
        }else{
            flag = flag;
        }
        /*-------------------------------- copyed to here------------------*/
        p1=p1;
        iter_count1=iter_count1;
    }
    /*---------------------constant loop stop------------------*/
    if(flag==0)
    {
//        printf("Substring NOT found");
        return 0;
    }else{
        return 1;
    }
}

sgx_status_t enclave_ids(uint8_t* cyphertext, size_t lSize,
                         uint8_t* en_mac,size_t* oSize,uint8_t* encProcessedtext, size_t* matched)
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
    char matchString[] = "<script>onerror=alert;throw 1</script>";
    *oSize=lSize;
    *matched = matching((char*)cyphertext,matchString);
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



/* Our compression codebook, used for compression */
static char *Smaz_cb[241] = {
        "\002s,\266", "\003had\232\002leW", "\003on \216", "", "\001yS",
        "\002ma\255\002li\227", "\003or \260", "", "\002ll\230\003s t\277",
        "\004fromg\002mel", "", "\003its\332", "\001z\333", "\003ingF", "\001>\336",
        "\001 \000\003   (\002nc\344", "\002nd=\003 on\312",
        "\002ne\213\003hat\276\003re q", "", "\002ngT\003herz\004have\306\003s o\225",
        "", "\003ionk\003s a\254\002ly\352", "\003hisL\003 inN\003 be\252", "",
        "\003 fo\325\003 of \003 ha\311", "", "\002of\005",
        "\003 co\241\002no\267\003 ma\370", "", "", "\003 cl\356\003enta\003 an7",
        "\002ns\300\001\"e", "\003n t\217\002ntP\003s, \205",
        "\002pe\320\003 we\351\002om\223", "\002on\037", "", "\002y G", "\003 wa\271",
        "\003 re\321\002or*", "", "\002=\"\251\002ot\337", "\003forD\002ou[",
        "\003 toR", "\003 th\r", "\003 it\366",
        "\003but\261\002ra\202\003 wi\363\002</\361", "\003 wh\237", "\002  4",
        "\003nd ?", "\002re!", "", "\003ng c", "",
        "\003ly \307\003ass\323\001a\004\002rir", "", "", "", "\002se_", "\003of \"",
        "\003div\364\002ros\003ere\240", "", "\002ta\310\001bZ\002si\324", "",
        "\003and\a\002rs\335", "\002rt\362", "\002teE", "\003ati\316", "\002so\263",
        "\002th\021", "\002tiJ\001c\034\003allp", "\003ate\345", "\002ss\246",
        "\002stM", "", "\002><\346", "\002to\024", "\003arew", "\001d\030",
        "\002tr\303", "", "\001\n1\003 a \222", "\003f tv\002veo", "\002un\340", "",
        "\003e o\242", "\002a \243\002wa\326\001e\002", "\002ur\226\003e a\274",
        "\002us\244\003\n\r\n\247", "\002ut\304\003e c\373", "\002we\221", "", "",
        "\002wh\302", "\001f,", "", "", "", "\003d t\206", "", "", "\003th \343",
        "\001g;", "", "", "\001\r9\003e s\265", "\003e t\234", "", "\003to Y",
        "\003e\r\n\236", "\002d \036\001h\022", "", "\001,Q", "\002 a\031", "\002 b^",
        "\002\r\n\025\002 cI", "\002 d\245", "\002 e\253", "\002 fh\001i\b\002e \v",
        "", "\002 hU\001-\314", "\002 i8", "", "", "\002 l\315", "\002 m{",
        "\002f :\002 n\354", "\002 o\035", "\002 p}\001.n\003\r\n\r\250", "",
        "\002 r\275", "\002 s>", "\002 t\016", "", "\002g \235\005which+\003whi\367",
        "\002 w5", "\001/\305", "\003as \214", "\003at \207", "", "\003who\331", "",
        "\001l\026\002h \212", "", "\002, $", "", "\004withV", "", "", "", "\001m-", "",
        "", "\002ac\357", "\002ad\350", "\003TheH", "", "", "\004this\233\001n\t",
        "", "\002. y", "", "\002alX\003e, \365", "\003tio\215\002be\\",
        "\002an\032\003ver\347", "", "\004that0\003tha\313\001o\006", "\003was2",
        "\002arO", "\002as.", "\002at'\003the\001\004they\200\005there\322\005theird",
        "\002ce\210", "\004were]", "", "\002ch\231\002l \264\001p<", "", "",
        "\003one\256", "", "\003he \023\002dej", "\003ter\270", "\002cou", "",
        "\002by\177\002di\201\002eax", "", "\002ec\327", "\002edB", "\002ee\353", "",
        "", "\001r\f\002n )", "", "", "", "\002el\262", "", "\003in i\002en3", "",
        "\002o `\001s\n", "", "\002er\033", "\003is t\002es6", "", "\002ge\371",
        "\004.com\375", "\002fo\334\003our\330", "\003ch \301\001t\003", "\002hab", "",
        "\003men\374", "", "\002he\020", "", "", "\001u&", "\002hif", "",
        "\003not\204\002ic\203", "\003ed @\002id\355", "", "", "\002ho\273",
        "\002r K\001vm", "", "", "", "\003t t\257\002il\360", "\002im\342",
        "\003en \317\002in\017", "\002io\220", "\002s \027\001wA", "", "\003er |",
        "\003es ~\002is%", "\002it/", "", "\002iv\272", "",
        "\002t #\ahttp://C\001x\372", "\002la\211", "\001<\341", "\003, a\224"
};

/* Reverse compression codebook, used for decompression */
static char *Smaz_rcb[254] = {
        " ", "the", "e", "t", "a", "of", "o", "and", "i", "n", "s", "e ", "r", " th",
        " t", "in", "he", "th", "h", "he ", "to", "\r\n", "l", "s ", "d", " a", "an",
        "er", "c", " o", "d ", "on", " of", "re", "of ", "t ", ", ", "is", "u", "at",
        "   ", "n ", "or", "which", "f", "m", "as", "it", "that", "\n", "was", "en",
        "  ", " w", "es", " an", " i", "\r", "f ", "g", "p", "nd", " s", "nd ", "ed ",
        "w", "ed", "http://", "for", "te", "ing", "y ", "The", " c", "ti", "r ", "his",
        "st", " in", "ar", "nt", ",", " to", "y", "ng", " h", "with", "le", "al", "to ",
        "b", "ou", "be", "were", " b", "se", "o ", "ent", "ha", "ng ", "their", "\"",
        "hi", "from", " f", "in ", "de", "ion", "me", "v", ".", "ve", "all", "re ",
        "ri", "ro", "is ", "co", "f t", "are", "ea", ". ", "her", " m", "er ", " p",
        "es ", "by", "they", "di", "ra", "ic", "not", "s, ", "d t", "at ", "ce", "la",
        "h ", "ne", "as ", "tio", "on ", "n t", "io", "we", " a ", "om", ", a", "s o",
        "ur", "li", "ll", "ch", "had", "this", "e t", "g ", "e\r\n", " wh", "ere",
        " co", "e o", "a ", "us", " d", "ss", "\n\r\n", "\r\n\r", "=\"", " be", " e",
        "s a", "ma", "one", "t t", "or ", "but", "el", "so", "l ", "e s", "s,", "no",
        "ter", " wa", "iv", "ho", "e a", " r", "hat", "s t", "ns", "ch ", "wh", "tr",
        "ut", "/", "have", "ly ", "ta", " ha", " on", "tha", "-", " l", "ati", "en ",
        "pe", " re", "there", "ass", "si", " fo", "wa", "ec", "our", "who", "its", "z",
        "fo", "rs", ">", "ot", "un", "<", "im", "th ", "nc", "ate", "><", "ver", "ad",
        " we", "ly", "ee", " n", "id", " cl", "ac", "il", "</", "rt", " wi", "div",
        "e, ", " it", "whi", " ma", "ge", "x", "e c", "men", ".com"
};

int smaz_compress(char *in, int inlen, char *out, int outlen) {
    unsigned int h1,h2,h3=0;
    int verblen = 0, _outlen = outlen;
    char verb[256], *_out = out;

    while(inlen) {
        int j = 7, needed;
        char *flush = NULL;
        char *slot;

        h1 = h2 = in[0]<<3;
        if (inlen > 1) h2 += in[1];
        if (inlen > 2) h3 = h2^in[2];
        if (j > inlen) j = inlen;

        /* Try to lookup substrings into the hash table, starting from the
         * longer to the shorter substrings */
        for (; j > 0; j--) {
            switch(j) {
                case 1: slot = Smaz_cb[h1%241]; break;
                case 2: slot = Smaz_cb[h2%241]; break;
                default: slot = Smaz_cb[h3%241]; break;
            }
            while(slot[0]) {
                if (slot[0] == j && memcmp(slot+1,in,j) == 0) {
                    /* Match found in the hash table,
                     * prepare a verbatim bytes flush if needed */
                    if (verblen) {
                        needed = (verblen == 1) ? 2 : 2+verblen;
                        flush = out;
                        out += needed;
                        outlen -= needed;
                    }
                    /* Emit the byte */
                    if (outlen <= 0) return _outlen+1;
                    out[0] = slot[slot[0]+1];
                    out++;
                    outlen--;
                    inlen -= j;
                    in += j;
                    goto out;
                } else {
                    slot += slot[0]+2;
                }
            }
        }
        /* Match not found - add the byte to the verbatim buffer */
        verb[verblen] = in[0];
        verblen++;
        inlen--;
        in++;
        out:
        /* Prepare a flush if we reached the flush length limit, and there
         * is not already a pending flush operation. */
        if (!flush && (verblen == 256 || (verblen > 0 && inlen == 0))) {
            needed = (verblen == 1) ? 2 : 2+verblen;
            flush = out;
            out += needed;
            outlen -= needed;
            if (outlen < 0) return _outlen+1;
        }
        /* Perform a verbatim flush if needed */
        if (flush) {
            if (verblen == 1) {
                flush[0] = (signed char)254;
                flush[1] = verb[0];
            } else {
                flush[0] = (signed char)255;
                flush[1] = (signed char)(verblen-1);
                memcpy(flush+2,verb,verblen);
            }
            flush = NULL;
            verblen = 0;
        }
    }
    return out-_out;
}

sgx_status_t enclave_compression(uint8_t* cyphertext, size_t lSize,
                                 uint8_t* en_mac,size_t* oSize,uint8_t* encProcessedtext)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t* storage = (uint8_t*) malloc(lSize);
    ret = sgx_rijndael128GCM_decrypt(
            (const sgx_ec_key_128bit_t*) data_key, //(const sgx_ec_key_128bit_t*) g_secret_DO,
            cyphertext,
            lSize,
            storage,
            aes_gcm_iv,
            12,
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t*) en_mac);

//    char matchString[] = "alert(1)";
    *oSize=(size_t)smaz_compress((char*)storage,lSize,(char*)encProcessedtext,lSize);
//    *matched = matching((char*)cyphertext,matchString);

    *oSize=get_padding_size(*oSize);
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