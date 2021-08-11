/*
 * ahocorasick.h: The main ahocorasick header file.
 * This file is part of multifast.
 *
    Copyright 2010-2015 Kamiar Kanani <kamiar.kanani@gmail.com>

    multifast is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    multifast is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with multifast.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _AHOCORASICK_H_
#define _AHOCORASICK_H_

#include <stdlib.h>
#include "Enclave.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
* actypes.h
* ***************************************
*/

/**
 * @brief The alphabet type
 *
 * Actually defining AC_ALPHABET_t as a char works for many usage case, but
 * sometimes we deal with streams of other basic types e.g. integers or
 * enumerators. Although they consists of string of bytes (chars), but using
 * their specific types as AC_ALPHABET_t will lead to a better performance.
 * So instead of working with strings of chars, we assume that we are working
 * with strings of AC_ALPHABET_t and leave it optional for users to define
 * their own alphabets.
 */
typedef char AC_ALPHABET_t;

/**
 * The text (strings of alphabets) type that is used for input/output when
 * dealing with the A.C. Trie. The text can contain zero value alphabets.
 */
typedef struct ac_text
{
    const AC_ALPHABET_t *astring;   /**< String of alphabets */
    size_t length;                  /**< String length */
} AC_TEXT_t;

/**
 * Pattern ID type
 * @see struct ac_pattid
 */
enum ac_pattid_type
{
    AC_PATTID_TYPE_DEFAULT = 0,
    AC_PATTID_TYPE_NUMBER,
    AC_PATTID_TYPE_STRING
};

/**
 * Provides a more readable representative for the pattern. Because patterns
 * themselves are not always suitable for displaying (e.g. patterns containing
 * special characters), we offer this type to improve intelligibility of the
 * output. Sometimes it can be also useful, when you are retrieving patterns
 * from a database, to maintain their identifiers in the trie for further
 * reference. We provisioned two possible types as a union. you can add your
 * type here.
 */
typedef struct ac_pattid
{
    union
    {
        const char *stringy;    /**< Null-terminated string */
        long number;            /**< Item indicator */
    } u;

    enum ac_pattid_type type;   /**< Shows the type of id */

} AC_PATTID_t;

/**
 * This is the pattern type that the trie must be fed by.
 */
typedef struct ac_pattern
{
    AC_TEXT_t ptext;    /**< The search string */
    AC_TEXT_t rtext;    /**< The replace string */
    AC_PATTID_t id;   /**< Pattern identifier */
} AC_PATTERN_t;

/**
 * @brief Provides the structure for reporting a match in the text.
 *
 * A match occurs when the trie reaches a final node. Any final
 * node can match one or more patterns at a position in the input text.
 * the 'patterns' field holds these matched patterns. Obviously these
 * matched patterns have same end-position in the text. There is a relationship
 * between matched patterns: the shorter one is a factor (tail) of the longer
 * one. The 'position' maintains the end position of matched patterns.
 */
typedef struct ac_match
{
    AC_PATTERN_t *patterns;     /**< Array of matched pattern(s) */
    size_t size;                /**< Number of matched pattern(s) */
    size_t position;    /**< The end position of the matching pattern(s) in
                         * the input text */
} AC_MATCH_t;

/**
 * The return status of various A.C. Trie functions
 */
typedef enum ac_status
{
    ACERR_SUCCESS = 0,          /**< No error occurred */
    ACERR_DUPLICATE_PATTERN,    /**< Duplicate patterns */
    ACERR_LONG_PATTERN,         /**< Pattern length is too long */
    ACERR_ZERO_PATTERN,         /**< Empty pattern (zero length) */
    ACERR_TRIE_CLOSED       /**< Trie is closed. */
} AC_STATUS_t;

/**
 * @ brief The call-back function to report the matched patterns back to the
 * caller.
 *
 * When a match is found, the trie will reach the caller using this
 * function. You can send parameters to the call-back function when you call
 * _search() or _replace() functions. The call-back function receives those
 * parameters as the second parameter determined by void * in bellow. If you
 * return 0 from call-back function, it will tell trie to continue
 * searching, otherwise it will return from the trie function.
 */
typedef int (*AC_MATCH_CALBACK_f)(AC_MATCH_t *, void *);

/**
 * @brief Call-back function to receive the replacement text (chunk by chunk).
 */
typedef void (*MF_REPLACE_CALBACK_f)(AC_TEXT_t *, void *);

/**
 * Maximum accepted length of search/replace pattern
 */
#define AC_PATTRN_MAX_LENGTH 4096
//#define AC_PATTRN_MAX_LENGTH 4096

/**
 * Replacement buffer size
 */
#define MF_REPLACEMENT_BUFFER_SIZE 1048576
//#define MF_REPLACEMENT_BUFFER_SIZE 4096

#if (MF_REPLACEMENT_BUFFER_SIZE <= AC_PATTRN_MAX_LENGTH)
#error "REPLACEMENT_BUFFER_SIZE must be bigger than AC_PATTRN_MAX_LENGTH"
#endif

typedef enum act_working_mode
{
    AC_WORKING_MODE_SEARCH = 0, /* Default */
    AC_WORKING_MODE_FINDNEXT,
    AC_WORKING_MODE_REPLACE     /* Not used */
} ACT_WORKING_MODE_t;

/*
* node.h
* ***************************************
*/


/* Forward Declaration */
struct act_edge;
struct ac_trie;

/**
 * Aho-Corasick Trie node
 */
typedef struct act_node
{
    int id;     /**< Node identifier: used for debugging purpose */

    int final;      /**< A final node accepts pattern; 0: not, 1: is final */
    size_t depth;   /**< Distance between this node and the root */
    struct act_node *failure_node;  /**< The failure transition node */

    struct act_edge *outgoing;  /**< Outgoing edges array */
    size_t outgoing_capacity;   /**< Max capacity of outgoing edges */
    size_t outgoing_size;       /**< Number of outgoing edges */

    AC_PATTERN_t *matched;      /**< Matched patterns array */
    size_t matched_capacity;    /**< Max capacity of the matched patterns */
    size_t matched_size;        /**< Number of matched patterns in this node */

    AC_PATTERN_t *to_be_replaced;   /**< Pointer to the pattern that must be
                                     * replaced */

    struct ac_trie *trie;    /**< The trie that this node belongs to */

} ACT_NODE_t;

/**
 * Edge of the node
 */
struct act_edge
{
    AC_ALPHABET_t alpha;    /**< Transition alpha */
    ACT_NODE_t *next;       /**< Target of the edge */
};

/*
 * Node interface functions
 */

ACT_NODE_t *node_create (struct ac_trie *trie);
ACT_NODE_t *node_create_next (ACT_NODE_t *nod, AC_ALPHABET_t alpha);
ACT_NODE_t *node_find_next (ACT_NODE_t *nod, AC_ALPHABET_t alpha);
ACT_NODE_t *node_find_next_bs (ACT_NODE_t *nod, AC_ALPHABET_t alpha);

void node_assign_id (ACT_NODE_t *nod);
void node_add_edge (ACT_NODE_t *nod, ACT_NODE_t *next, AC_ALPHABET_t alpha);
void node_sort_edges (ACT_NODE_t *nod);
void node_accept_pattern (ACT_NODE_t *nod, AC_PATTERN_t *new_patt, int copy);
void node_collect_matches (ACT_NODE_t *nod);
void node_release_vectors (ACT_NODE_t *nod);
int  node_book_replacement (ACT_NODE_t *nod);
void node_display (ACT_NODE_t *nod);

/*
* mpool.h
* ***************************************
*/


/* Forward declaration */
struct mpool;


struct mpool *mpool_create (size_t size);
void mpool_free (struct mpool *pool);

void *mpool_malloc (struct mpool *pool, size_t size);
void *mpool_strdup (struct mpool *pool, const char *str);
void *mpool_strndup (struct mpool *pool, const char *str, size_t n);

/*
* replace.h
* ***************************************
*/

/**
 * Different replace modes
 */
typedef enum mf_replace_mode
{
    MF_REPLACE_MODE_DEFAULT = 0,
    MF_REPLACE_MODE_NORMAL, /**< Normal replace mode: Short factors are swollen
                              * by the big one; All other patterns are replced
                              * even if they have overlap.
                              */
    MF_REPLACE_MODE_LAZY   /**< Lazy replace mode: every pattern which comes
                             * first is replced; the overlapping pattrns are
                             * nullified by the previous patterns; consequently,
                             * factor patterns nullify the big patterns.
                             */
} MF_REPLACE_MODE_t;


/**
 * Before we replace any pattern we encounter, we should be patient
 * because it may be a factor of another longer pattern. So we maintain a record
 * of each recognized pattern until we make sure that it is not a sub-pattern
 * and can be replaced by its substitute. To keep a record of packets we use
 * the following structure.
 */
struct mf_replacement_nominee
{
    AC_PATTERN_t *pattern;
    size_t position;
};


/**
 * Contains replacement related data
 */
typedef struct mf_replacement_date
{
    AC_TEXT_t buffer;   /**< replacement buffer: maintains the result
                         * of replacement */

    AC_TEXT_t backlog;  /**< replacement backlog: if a pattern is divided
                         * between two or more different chunks, then at the
                         * end of the first chunk we need to keep it here until
                         * the next chunk comes and we decide if it is a
                         * pattern or just a pattern prefix. */

    unsigned int has_replacement; /**< total number of to-be-replaced patterns
                                   */

    struct mf_replacement_nominee *noms; /**< Replacement nominee array */
    size_t noms_capacity; /**< Max capacity of the array */
    size_t noms_size;  /**< Number of nominees in the array */

    size_t curser; /**< the position in the input text before which all
                    * patterns are replaced and the result is saved to the
                    * buffer. */

    MF_REPLACE_MODE_t replace_mode;  /**< Replace mode */

    MF_REPLACE_CALBACK_f cbf;   /**< Callback function */
    void *user;    /**< User parameters sent to the callback function */

    struct ac_trie *trie; /**< Pointer to the trie */

} MF_REPLACEMENT_DATA_t;


/*
 * ahocorasick.h
 * ***************************************
 */
/* Forward declaration */
struct act_node;
struct mpool;

/* 
 * The A.C. Trie data structure 
 */
typedef struct ac_trie
{
    struct act_node *root;      /**< The root node of the trie */
    
    size_t patterns_count;      /**< Total patterns in the trie */
    
    short trie_open; /**< This flag indicates that if trie is finalized 
                          * or not. After finalizing the trie you can not 
                          * add pattern to trie anymore. */
    
    struct mpool *mp;   /**< Memory pool */
    
    /* ******************* Thread specific part ******************** */
    
    /* It is possible to search a long input chunk by chunk. In order to
     * connect these chunks and make a continuous view of the input, we need 
     * the following variables.
     */
    struct act_node *last_node; /**< Last node we stopped at */
    size_t base_position; /**< Represents the position of the current chunk,
                           * related to whole input text */
    
    AC_TEXT_t *text;    /**< A helper variable to hold the input chunk */
    size_t position;    /**< A helper variable to hold the relative current 
                         * position in the given text */
    
    MF_REPLACEMENT_DATA_t repdata;    /**< Replacement data structure */
    
    ACT_WORKING_MODE_t wm; /**< Working mode */
        
} AC_TRIE_t;

/* 
 * The API functions
 */

AC_TRIE_t *ac_trie_create (void);
AC_STATUS_t ac_trie_add (AC_TRIE_t *thiz, AC_PATTERN_t *patt, int copy);
void ac_trie_finalize (AC_TRIE_t *thiz);
void ac_trie_release (AC_TRIE_t *thiz);
void ac_trie_display (AC_TRIE_t *thiz);

int  ac_trie_search (AC_TRIE_t *thiz, AC_TEXT_t *text, int keep, 
        AC_MATCH_CALBACK_f callback, void *param);

void ac_trie_settext (AC_TRIE_t *thiz, AC_TEXT_t *text, int keep);
AC_MATCH_t ac_trie_findnext (AC_TRIE_t *thiz);

int  multifast_replace (AC_TRIE_t *thiz, AC_TEXT_t *text, 
        MF_REPLACE_MODE_t mode, MF_REPLACE_CALBACK_f callback, void *param);
void multifast_rep_flush (AC_TRIE_t *thiz, int keep);


#ifdef __cplusplus
}
#endif

#endif
