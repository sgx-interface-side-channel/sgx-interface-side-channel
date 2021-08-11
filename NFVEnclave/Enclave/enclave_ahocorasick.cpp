/*
 * ahocorasick.c: Implements the A. C. Trie functionalities
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

#include <string.h>
#include <ctype.h>
#include "ahocorasick.h"

#define MPOOL_BLOCK_SIZE (24*4096)

#if (MPOOL_BLOCK_SIZE % 16 > 0)
#error "MPOOL_BLOCK_SIZE must be multiple 16"
#endif

#if (MPOOL_BLOCK_SIZE <= AC_PATTRN_MAX_LENGTH)
#error "MPOOL_BLOCK_SIZE must be bigger than AC_PATTRN_MAX_LENGTH"
#endif

struct mpool_block
{
    size_t size;
    unsigned char *bp;      /* Block pointer */
    unsigned char *free;    /* Free area; End of allocated section */

    struct mpool_block *next; /* Next block */
};

struct mpool
{
    struct mpool_block *block;
};


/**
 * @brief Allocate a new block to the pool
 *
 * @param size
 * @return
******************************************************************************/
static struct mpool_block *mpool_new_block (size_t size)
{
    struct mpool_block *block;

    if (!size){
        size = MPOOL_BLOCK_SIZE;
    }else{
        size = size;
    }


    block = (struct mpool_block *) malloc (sizeof(struct mpool_block));

    block->bp = block->free = (unsigned char*)malloc(size);
    block->size = size;
    block->next = NULL;

    return block;
}

/**
 * @brief Creates a new pool
 *
 * @param size
 * @return
******************************************************************************/
struct mpool *mpool_create (size_t size)
{
    struct mpool *ret;

    ret = (mpool*) malloc (sizeof(struct mpool));
    ret->block = mpool_new_block(size);

    return ret;
}

/**
 * @brief Free a pool
 *
 * @param pool
******************************************************************************/
void mpool_free (struct mpool *pool)
{
    struct mpool_block *p, *p_next;

    if (!pool)
        return;

    if (!pool->block) {
        free(pool);
        return;
    }

    p = pool->block;

    while (p) {
        p_next = p->next;
        free(p->bp);
        free(p);
        p = p_next;
    }

    free(pool);
}

/**
 * @brief Allocate from a pool
 *
 * @param pool
 * @param size
 * @return
******************************************************************************/
void *mpool_malloc (struct mpool *pool, size_t size)
{
    void *ret = NULL;
    struct mpool_block *block, *new_block;
    size_t remain, block_size;

    if(!pool || !pool->block || !size){
        return NULL;
    }

    size = (size + 15) & ~0xF; /* This is to align memory allocation on
                                * multiple 16 boundary */

    block = pool->block;
    remain = block->size - ((size_t)block->free - (size_t)block->bp);

    if (remain < size)
    {
        /* Allocate a new block */
        block_size = ((size > block->size) ? size : block->size);
        new_block = mpool_new_block (block_size);
        new_block->next = block;
        block = pool->block = new_block;
    }

    ret = block->free;

    block->free = block->bp + (block->free - block->bp + size);

    return ret;
}

/**
 * @brief Makes a copy of a string with known size
 *
 * @param pool
 * @param str
 * @param n
 * @return
 *****************************************************************************/
void *mpool_strndup (struct mpool *pool, const char *str, size_t n)
{
    void *ret;

    if (!str)
        return NULL;

    if ((ret = mpool_malloc(pool, n+1)))
    {
        strncpy((char *)ret, str, n);
        ((char *)ret)[n] = '\0';
    }

    return ret;
}

/**
 * @brief Makes a copy of zero terminated string
 *
 * @param pool
 * @param str
 * @return
******************************************************************************/
void *mpool_strdup (struct mpool *pool, const char *str)
{
    size_t len;

    if (!str)
        return NULL;
    len = strlen(str);

    return mpool_strndup (pool, str, len);
}



/* Privates */
static void node_init (ACT_NODE_t *thiz);
static int  node_edge_compare (const void *l, const void *r);
static int  node_has_pattern (ACT_NODE_t *thiz, AC_PATTERN_t *patt);
static void node_grow_outgoing_vector (ACT_NODE_t *thiz);
static void node_grow_matched_vector (ACT_NODE_t *thiz);
static void node_copy_pattern (ACT_NODE_t *thiz,
                               AC_PATTERN_t *to, AC_PATTERN_t *from);

/**
 * @brief Creates the node
 *
 * @return
******************************************************************************/
struct act_node * node_create (struct ac_trie *trie)
{
    ACT_NODE_t *node;

    node = (ACT_NODE_t *) mpool_malloc (trie->mp, sizeof(ACT_NODE_t));
    node_init (node);
    node->trie = trie;

    return node;
}

/**
 * @brief Initializes the node
 *
 * @param thiz
 *****************************************************************************/
static void node_init (ACT_NODE_t *thiz)
{
    node_assign_id (thiz);

    thiz->final = 0;
    thiz->failure_node = NULL;
    thiz->depth = 0;

    thiz->matched = NULL;
    thiz->matched_capacity = 0;
    thiz->matched_size = 0;

    thiz->outgoing = NULL;
    thiz->outgoing_capacity = 0;
    thiz->outgoing_size = 0;

    thiz->to_be_replaced = NULL;
}

/**
 * @brief Releases the node memories
 *
 * @param thiz
 *****************************************************************************/
void node_release_vectors(ACT_NODE_t *nod)
{
    free(nod->matched);
    free(nod->outgoing);
}

/**
 * @brief Finds out the next node for a given alpha. this function is used in
 * the pre-processing stage in which edge array is not sorted. so it uses
 * linear search.
 *
 * @param thiz
 * @param alpha
 * @return
 *****************************************************************************/
ACT_NODE_t * node_find_next(ACT_NODE_t *nod, AC_ALPHABET_t alpha)
{
    size_t i;

    for (i=0; i < nod->outgoing_size; i++)
    {
        if(nod->outgoing[i].alpha == alpha)
            return (nod->outgoing[i].next);
    }
    return NULL;
}

/**
 * @brief Finds out the next node for a given alpha. this function is used
 * after the pre-processing stage in which we sort edges. so it uses Binary
 * Search.
 *
 * @param thiz
 * @param alpha
 * @return
 *****************************************************************************/
ACT_NODE_t *node_find_next_bs (ACT_NODE_t *nod, AC_ALPHABET_t alpha)
{
    size_t mid;
    int min, max;
    AC_ALPHABET_t amid;

    min = 0;
    max = nod->outgoing_size - 1;

    while (min <= max)
    {
        mid = (min + max) >> 1;
        amid = nod->outgoing[mid].alpha;
        if (alpha > amid)
            min = mid + 1;
        else if (alpha < amid)
            max = mid - 1;
        else
            return (nod->outgoing[mid].next);
    }
    return NULL;
}

/**
 * @brief Determines if a final node contains a pattern in its accepted pattern
 * list or not.
 *
 * @param thiz
 * @param newstr
 * @return 1: has the pattern, 0: doesn't have it
 *****************************************************************************/
static int node_has_pattern (ACT_NODE_t *thiz, AC_PATTERN_t *patt)
{
    size_t i, j;
    AC_TEXT_t *txt;
    AC_TEXT_t *new_txt = &patt->ptext;

    for (i = 0; i < thiz->matched_size; i++)
    {
        txt = &thiz->matched[i].ptext;

        if (txt->length != new_txt->length)
            continue;

        /* The following loop is futile! Because the input pattern always come
         * from a failure node, and if they have the same length, then they are
         * equal. But for the sake of functional integrity we leave it here. */

        for (j = 0; j < txt->length; j++)
            if (txt->astring[j] != new_txt->astring[j])
                break;

        if (j == txt->length)
            return 1;
    }
    return 0;
}

/**
 * @brief Create the next node for the given alpha.
 *
 * @param thiz
 * @param alpha
 * @return
 *****************************************************************************/
ACT_NODE_t *node_create_next (ACT_NODE_t *nod, AC_ALPHABET_t alpha)
{
    ACT_NODE_t *next;

    if (node_find_next (nod, alpha) != NULL)
        /* The edge already exists */
        return NULL;

    next = node_create (nod->trie);
    node_add_edge (nod, next, alpha);

    return next;
}

/**
 * @brief Adds the pattern to the list of accepted pattern.
 *
 * @param thiz
 * @param str
 * @param copy
 *****************************************************************************/
void node_accept_pattern (ACT_NODE_t *nod, AC_PATTERN_t *new_patt, int copy)
{
    AC_PATTERN_t *patt;

    /* Check if the new pattern already exists in the node list */
    if (node_has_pattern(nod, new_patt))
        return;

    /* Manage memory */
    if (nod->matched_size == nod->matched_capacity)
        node_grow_matched_vector (nod);

    patt = &nod->matched[nod->matched_size++];

    if (copy)
    {
        /* Deep copy */
        node_copy_pattern (nod, patt, new_patt);
    }
    else
    {
        /* Shallow copy */
        *patt = *new_patt;
    }
}

/**
 * @brief Makes a deep copy of the pattern
 *
 * @param thiz pointer to the owner node
 * @param from
 * @param to
 *****************************************************************************/
static void node_copy_pattern
        (ACT_NODE_t *thiz, AC_PATTERN_t *to, AC_PATTERN_t *from)
{
    struct mpool *mp = thiz->trie->mp;

    to->ptext.astring = (AC_ALPHABET_t *) mpool_strndup (mp,
                                                         (const char *) from->ptext.astring,
                                                         from->ptext.length * sizeof(AC_ALPHABET_t));
    to->ptext.length = from->ptext.length;

    to->rtext.astring = (AC_ALPHABET_t *) mpool_strndup (mp,
                                                         (const char *) from->rtext.astring,
                                                         from->rtext.length * sizeof(AC_ALPHABET_t));
    to->rtext.length = from->rtext.length;

    if (from->id.type == AC_PATTID_TYPE_STRING)
        to->id.u.stringy = (const char *) mpool_strdup (mp,
                                                        (const char *) from->id.u.stringy);
    else
        to->id.u.number = from->id.u.number;

    to->id.type = from->id.type;
}

/**
 * @brief Establish an edge between two nodes
 *
 * @param thiz
 * @param next
 * @param alpha
 *****************************************************************************/
void node_add_edge (ACT_NODE_t *nod, ACT_NODE_t *next, AC_ALPHABET_t alpha)
{
    struct act_edge *oe; /* Outgoing edge */

    if(nod->outgoing_size == nod->outgoing_capacity)
        node_grow_outgoing_vector (nod);

    oe = &nod->outgoing[nod->outgoing_size];
    oe->alpha = alpha;
    oe->next = next;
    nod->outgoing_size++;
}

/**
 * @brief Assigns a unique ID to the node (used for debugging purpose)
 *
 * @param thiz
 *****************************************************************************/
void node_assign_id (ACT_NODE_t *nod)
{
    static int unique_id = 1;
    nod->id = unique_id++;
}

/**
 * @brief Comparison function for qsort. see man qsort.
 *
 * @param l left side
 * @param r right side
 * @return According to the man page: The comparison function must return an
 * integer less than, equal to, or greater than zero if the first argument is
 * considered to be respectively less than, equal to, or greater than the
 * second. if two members compare as equal, their order in the sorted array is
 * undefined.
 *****************************************************************************/
static int node_edge_compare (const void *l, const void *r)
{
    /*
     * NOTE: Because edge alphabets are unique in every node we ignore
     * equivalence case.
     */
    if (((struct act_edge *)l)->alpha >= ((struct act_edge *)r)->alpha)
        return 1;
    else
        return -1;
}

/**
 * @brief Sorts edges alphabets.
 *
 * @param thiz
 *****************************************************************************/
void node_sort_edges (ACT_NODE_t *nod)
{
    qsort ((void *)nod->outgoing, nod->outgoing_size,
           sizeof(struct act_edge), node_edge_compare);
}

/**
 * @brief Bookmarks the to-be-replaced patterns
 *
 * If there was more than one pattern accepted in a node then only one of them
 * must be replaced: The longest pattern that has a requested replacement.
 *
 * @param node
 * @return 1 if there was any replacement, 0 otherwise
 *****************************************************************************/
int node_book_replacement (ACT_NODE_t *nod)
{
    size_t j;
    AC_PATTERN_t *pattern;
    AC_PATTERN_t *longest = NULL;

    if(!nod->final)
        return 0;

    for (j=0; j < nod->matched_size; j++)
    {
        pattern = &nod->matched[j];

        if (pattern->rtext.astring != NULL)
        {
            if (!longest)
                longest = pattern;
            else if (pattern->ptext.length > longest->ptext.length)
                longest = pattern;
        }
    }

    nod->to_be_replaced = longest;

    return longest ? 1 : 0;
}

/**
 * @brief Grows the size of outgoing edges vector
 *
 * @param thiz
 *****************************************************************************/
static void node_grow_outgoing_vector (ACT_NODE_t *thiz)
{
    const size_t grow_factor = (8 / (thiz->depth + 1)) + 1;

    /* The outgoing edges of nodes grow with different pace in different
     * depths; the shallower nodes the bigger outgoing number of nodes.
     * So for efficiency (speed & memory usage), we apply a measure to
     * manage different growth rate.
     */

    if (thiz->outgoing_capacity == 0)
    {
        thiz->outgoing_capacity = grow_factor;
        thiz->outgoing = (struct act_edge *) malloc
                (thiz->outgoing_capacity * sizeof(struct act_edge));
    }
    else
    {
        thiz->outgoing_capacity += grow_factor;
        thiz->outgoing = (struct act_edge *) realloc (
                thiz->outgoing,
                thiz->outgoing_capacity * sizeof(struct act_edge));
    }
}

/**
 * @brief Grows the size of matched patterns vector
 *
 * @param thiz
 *****************************************************************************/
static void node_grow_matched_vector (ACT_NODE_t *thiz)
{
    if (thiz->matched_capacity == 0)
    {
        thiz->matched_capacity = 1;
        thiz->matched = (AC_PATTERN_t *) malloc
                (thiz->matched_capacity * sizeof(AC_PATTERN_t));
    }
    else
    {
        thiz->matched_capacity += 2;
        thiz->matched = (AC_PATTERN_t *) realloc (
                thiz->matched,
                thiz->matched_capacity * sizeof(AC_PATTERN_t));
    }
}

/**
 * @brief Collect accepted patterns of the node.
 *
 * The accepted patterns consist of the node's own accepted pattern plus
 * accepted patterns of its failure node.
 *
 * @param node
 *****************************************************************************/
void node_collect_matches (ACT_NODE_t *nod)
{
    size_t i;
    ACT_NODE_t *n = nod;

    while ((n = n->failure_node))
    {
        for (i = 0; i < n->matched_size; i++)
            /* Always call with copy parameter 0 */
            node_accept_pattern (nod, &(n->matched[i]), 0);

        if (n->final)
            nod->final = 1;
    }

    node_sort_edges (nod);
    /* Sort matched patterns? Is that necessary? I don't think so. */
}

/**
 * @brief Displays all nodes recursively
 *
 * @param n
 * @param repcast
 *****************************************************************************/
void node_display (ACT_NODE_t *nod)
{
    size_t j;
    struct act_edge *e;
    AC_PATTERN_t patt;

    printf("NODE(%3d)/....fail....> ", nod->id);
    if (nod->failure_node)
        printf("NODE(%3d)\n", nod->failure_node->id);
    else
        printf ("N.A.\n");

    for (j = 0; j < nod->outgoing_size; j++)
    {
        e = &nod->outgoing[j];
        printf("         |----(");
        if(isgraph(e->alpha))
            printf("%c)---", e->alpha);
        else
            printf("0x%x)", e->alpha);
        printf("--> NODE(%3d)\n", e->next->id);
    }

    if (nod->matched_size)
    {
        printf("Accepts: {");
        for (j = 0; j < nod->matched_size; j++)
        {
            patt = nod->matched[j];
            if(j)
                printf(", ");
            switch (patt.id.type)
            {
                case AC_PATTID_TYPE_DEFAULT:
                case AC_PATTID_TYPE_NUMBER:
                    printf("%ld", patt.id.u.number);
                    break;
                case AC_PATTID_TYPE_STRING:
                    printf("%s", patt.id.u.stringy);
                    break;
            }
            printf(": %.*s", (int)patt.ptext.length, patt.ptext.astring);
        }
        printf("}\n");
    }
    printf("\n");
}

/* Privates */

static void ac_trie_set_failure
        (ACT_NODE_t *node, AC_ALPHABET_t *alphas);

static void ac_trie_traverse_setfailure
        (ACT_NODE_t *node, AC_ALPHABET_t *prefix);

static void ac_trie_traverse_action
        (ACT_NODE_t *node, void(*func)(ACT_NODE_t *), int top_down);

static void ac_trie_reset
        (AC_TRIE_t *thiz);

static int ac_trie_match_handler
        (AC_MATCH_t * matchp, void * param);

/* Friends */

extern void mf_repdata_init (AC_TRIE_t *thiz);
extern void mf_repdata_reset (MF_REPLACEMENT_DATA_t *rd);
extern void mf_repdata_release (MF_REPLACEMENT_DATA_t *rd);
extern void mf_repdata_allocbuf (MF_REPLACEMENT_DATA_t *rd);


/**
 * @brief Initializes the trie; allocates memories and sets initial values
 *
 * @return
 *****************************************************************************/
AC_TRIE_t *ac_trie_create (void)
{
    AC_TRIE_t *thiz = (AC_TRIE_t *) malloc (sizeof(AC_TRIE_t));
    thiz->mp = mpool_create(0);

    thiz->root = node_create (thiz);

    thiz->patterns_count = 0;

    mf_repdata_init (thiz);
    ac_trie_reset (thiz);
    thiz->text = NULL;
    thiz->position = 0;

    thiz->wm = AC_WORKING_MODE_SEARCH;
    thiz->trie_open = 1;

    return thiz;
}

/**
 * @brief Adds pattern to the trie.
 *
 * @param Thiz pointer to the trie
 * @param Patt pointer to the pattern
 * @param copy should trie make a copy of patten strings or not, if not,
 * then user must keep the strings valid for the life-time of the trie. If
 * the pattern are available in the user program then call the function with
 * copy = 0 and do not waste memory.
 *
 * @return The return value indicates the success or failure of adding action
 *****************************************************************************/
AC_STATUS_t ac_trie_add (AC_TRIE_t *thiz, AC_PATTERN_t *patt, int copy)
{
    size_t i;
    ACT_NODE_t *n = thiz->root;
    ACT_NODE_t *next;
    AC_ALPHABET_t alpha;

    if(!thiz->trie_open)
        return ACERR_TRIE_CLOSED;

    if (!patt->ptext.length)
        return ACERR_ZERO_PATTERN;

    if (patt->ptext.length > AC_PATTRN_MAX_LENGTH)
        return ACERR_LONG_PATTERN;

    for (i = 0; i < patt->ptext.length; i++)
    {
        alpha = patt->ptext.astring[i];
        if ((next = node_find_next (n, alpha)))
        {
            n = next;
            continue;
        }
        else
        {
            next = node_create_next (n, alpha);
            next->depth = n->depth + 1;
            n = next;
        }
    }

    if(n->final)
        return ACERR_DUPLICATE_PATTERN;

    n->final = 1;
    node_accept_pattern (n, patt, copy);
    thiz->patterns_count++;

    return ACERR_SUCCESS;
}

/**
 * @brief Finalizes the preprocessing stage and gets the trie ready
 *
 * Locates the failure node for all nodes and collects all matched
 * pattern for each node. It also sorts outgoing edges of node, so binary
 * search could be performed on them. After calling this function the automate
 * will be finalized and you can not add new patterns to the automate.
 *
 * @param thiz pointer to the trie
 *****************************************************************************/
void ac_trie_finalize (AC_TRIE_t *thiz)
{
    AC_ALPHABET_t prefix[AC_PATTRN_MAX_LENGTH];

    /* 'prefix' defined here, because ac_trie_traverse_setfailure() calls
     * itself recursively */
    ac_trie_traverse_setfailure (thiz->root, prefix);

    ac_trie_traverse_action (thiz->root, node_collect_matches, 1);
    mf_repdata_allocbuf (&thiz->repdata);

    thiz->trie_open = 0; /* Do not accept patterns any more */
}

/**
 * @brief Search in the input text using the given trie.
 *
 * @param thiz pointer to the trie
 * @param text input text to be searched
 * @param keep indicated that if the input text the successive chunk of the
 * previous given text or not
 * @param callback when a match occurs this function will be called. The
 * call-back function in turn after doing its job, will return an integer
 * value, 0 means continue search, and non-0 value means stop search and return
 * to the caller.
 * @param user this parameter will be send to the call-back function
 *
 * @return
 * -1:  failed; trie is not finalized
 *  0:  success; input text was searched to the end
 *  1:  success; input text was searched partially. (callback broke the loop)
 *****************************************************************************/
int ac_trie_search (AC_TRIE_t *thiz, AC_TEXT_t *text, int keep,
                    AC_MATCH_CALBACK_f callback, void *user)
{
    size_t position;
    ACT_NODE_t *current;
    ACT_NODE_t *next;
    AC_MATCH_t match;

    if (thiz->trie_open)
        return -1;  /* Trie must be finalized first. */

    if (thiz->wm == AC_WORKING_MODE_FINDNEXT)
        position = thiz->position;
    else
        position = 0;

    current = thiz->last_node;

    if (!keep)
        ac_trie_reset (thiz);

    /* This is the main search loop.
     * It must be kept as lightweight as possible.
     */
    while (position < text->length)
    {
        if (!(next = node_find_next_bs (current, text->astring[position])))
        {
            if(current->failure_node /* We are not in the root node */)
                current = current->failure_node;
            else
                position++;
        }
        else
        {
            current = next;
            position++;
        }

        if (current->final && next)
            /* We check 'next' to find out if we have come here after a alphabet
             * transition or due to a fail transition. in second case we should not
             * report match, because it has already been reported */
        {
            /* Found a match! */
            match.position = position + thiz->base_position;
            match.size = current->matched_size;
            match.patterns = current->matched;

            /* Do call-back */
            if (callback(&match, user))
            {
                if (thiz->wm == AC_WORKING_MODE_FINDNEXT) {
                    thiz->position = position;
                    thiz->last_node = current;
                }
                return 1;
            }
        }
    }

    /* Save status variables */
    thiz->last_node = current;
    thiz->base_position += position;

    return 0;
}

/**
 * @brief sets the input text to be searched by a function call to _findnext()
 *
 * @param thiz The pointer to the trie
 * @param text The text to be searched. The owner of the text is the
 * calling program and no local copy is made, so it must be valid until you
 * have done with it.
 * @param keep Indicates that if the given text is the sequel of the previous
 * one or not; 1: it is, 0: it is not
 *****************************************************************************/
void ac_trie_settext (AC_TRIE_t *thiz, AC_TEXT_t *text, int keep)
{
    if (!keep)
        ac_trie_reset (thiz);

    thiz->text = text;
    thiz->position = 0;
}

/**
 * @brief finds the next match in the input text which is set by _settext()
 *
 * @param thiz The pointer to the trie
 * @return A pointer to the matched structure
 *****************************************************************************/
AC_MATCH_t ac_trie_findnext (AC_TRIE_t *thiz)
{
    AC_MATCH_t match;

    thiz->wm = AC_WORKING_MODE_FINDNEXT;
    match.size = 0;

    ac_trie_search (thiz, thiz->text, 1,
                    ac_trie_match_handler, (void *)&match);

    thiz->wm = AC_WORKING_MODE_SEARCH;

    return match;
}

/**
 * @brief Release all allocated memories to the trie
 *
 * @param thiz pointer to the trie
 *****************************************************************************/
void ac_trie_release (AC_TRIE_t *thiz)
{
    /* It must be called with a 0 top-down parameter */
    ac_trie_traverse_action (thiz->root, node_release_vectors, 0);

    mf_repdata_release (&thiz->repdata);
    mpool_free(thiz->mp);
    free(thiz);
}

/**
 * @brief Prints the trie to output in human readable form. It is useful
 * for debugging purpose.
 *
 * @param thiz pointer to the trie
 *****************************************************************************/
void ac_trie_display (AC_TRIE_t *thiz)
{
    ac_trie_traverse_action (thiz->root, node_display, 1);
}

/**
 * @brief the match handler function used in _findnext function
 *
 * @param matchp
 * @param param
 * @return
 *****************************************************************************/
static int ac_trie_match_handler (AC_MATCH_t * matchp, void * param)
{
    AC_MATCH_t * mp = (AC_MATCH_t *)param;
    mp->position = matchp->position;
    mp->patterns = matchp->patterns;
    mp->size = matchp->size;
    return 1;
}

/**
 * @brief reset the trie and make it ready for doing new search
 *
 * @param thiz pointer to the trie
 *****************************************************************************/
static void ac_trie_reset (AC_TRIE_t *thiz)
{
    thiz->last_node = thiz->root;
    thiz->base_position = 0;
    mf_repdata_reset (&thiz->repdata);
}

/**
 * @brief Finds and bookmarks the failure transition for the given node.
 *
 * @param node the node pointer
 * @param prefix The array that contain the prefix that leads the path from
 * root the the node.
 *****************************************************************************/
static void ac_trie_set_failure
        (ACT_NODE_t *node, AC_ALPHABET_t *prefix)
{
    size_t i, j;
    ACT_NODE_t *n;
    ACT_NODE_t *root = node->trie->root;

    if (node == root)
        return; /* Failure transition is not defined for the root */

    for (i = 1; i < node->depth; i++)
    {
        n = root;
        for (j = i; j < node->depth && n; j++)
            n = node_find_next (n, prefix[j]);
        if (n)
        {
            node->failure_node = n;
            break;
        }
    }

    if (!node->failure_node)
        node->failure_node = root;
}

/**
 * @brief Sets the failure transition node for all nodes
 *
 * Traverse all trie nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function is called
 * after adding last pattern to trie.
 *
 * @param node The pointer to the root node
 * @param prefix The array that contain the prefix that leads the path from
 * root the the node
 *****************************************************************************/
static void ac_trie_traverse_setfailure
        (ACT_NODE_t *node, AC_ALPHABET_t *prefix)
{
    size_t i;

    /* In each node, look for its failure node */
    ac_trie_set_failure (node, prefix);

    for (i = 0; i < node->outgoing_size; i++)
    {
        prefix[node->depth] = node->outgoing[i].alpha; /* Make the prefix */

        /* Recursively call itself to traverse all nodes */
        ac_trie_traverse_setfailure (node->outgoing[i].next, prefix);
    }
}

/**
 * @brief Traverses the trie using DFS method and applies the
 * given @param func on all nodes. At top level it should be called by
 * sending the the root node.
 *
 * @param node Pointer to trie root node
 * @param func The function that must be applied to all nodes
 * @param top_down Indicates that if the action should be applied to the note
 * itself and then to its children or vise versa.
 *****************************************************************************/
static void ac_trie_traverse_action
        (ACT_NODE_t *node, void(*func)(ACT_NODE_t *), int top_down)
{
    size_t i;

    if (top_down)
        func (node);

    for (i = 0; i < node->outgoing_size; i++)
        /* Recursively call itself to traverse all nodes */
        ac_trie_traverse_action (node->outgoing[i].next, func, top_down);

    if (!top_down)
        func (node);
}



/**
 * @brief replace.c
 *****************************************************************************/

/* Privates */
static void mf_repdata_do_replace
        (MF_REPLACEMENT_DATA_t *rd, size_t to_position);

static void mf_repdata_booknominee
        (MF_REPLACEMENT_DATA_t *rd, struct mf_replacement_nominee *new_nom);

static void mf_repdata_push_nominee
        (MF_REPLACEMENT_DATA_t *rd, struct mf_replacement_nominee *new_nom);

static void mf_repdata_grow_noms_array
        (MF_REPLACEMENT_DATA_t *rd);

static void mf_repdata_appendtext
        (MF_REPLACEMENT_DATA_t *rd, AC_TEXT_t *text);

static void mf_repdata_appendfactor
        (MF_REPLACEMENT_DATA_t *rd, size_t from, size_t to);

static void mf_repdata_savetobacklog
        (MF_REPLACEMENT_DATA_t *rd, size_t to_position_r);

static void mf_repdata_flush
        (MF_REPLACEMENT_DATA_t *rd);

static unsigned int mf_repdata_bookreplacements
        (ACT_NODE_t *node);

/* Publics */

void mf_repdata_init (AC_TRIE_t *trie);
void mf_repdata_reset (MF_REPLACEMENT_DATA_t *rd);
void mf_repdata_release (MF_REPLACEMENT_DATA_t *rd);
void mf_repdata_allocbuf (MF_REPLACEMENT_DATA_t *rd);


/**
 * @brief Initializes the replacement data part of the trie
 *
 * @param trie
 *****************************************************************************/
void mf_repdata_init (AC_TRIE_t *trie)
{
    MF_REPLACEMENT_DATA_t *rd = &trie->repdata;

    rd->buffer.astring = NULL;
    rd->buffer.length = 0;
    rd->backlog.astring = NULL;
    rd->backlog.length = 0;
    rd->has_replacement = 0;
    rd->curser = 0;

    rd->noms = NULL;
    rd->noms_capacity = 0;
    rd->noms_size = 0;

    rd->replace_mode = MF_REPLACE_MODE_DEFAULT;
    rd->trie = trie;
}

/**
 * @brief Performs finalization tasks on replacement data.
 * Must be called when finalizing the trie itself
 *
 * @param rd
 *****************************************************************************/
void mf_repdata_allocbuf (MF_REPLACEMENT_DATA_t *rd)
{
    /* Bookmark replacement pattern for faster retrieval */
    rd->has_replacement = mf_repdata_bookreplacements (rd->trie->root);

    if (rd->has_replacement)
    {
        rd->buffer.astring = (AC_ALPHABET_t *)
                malloc (MF_REPLACEMENT_BUFFER_SIZE * sizeof(AC_ALPHABET_t));

        rd->backlog.astring = (AC_ALPHABET_t *)
                malloc (AC_PATTRN_MAX_LENGTH * sizeof(AC_ALPHABET_t));

        /* Backlog length is not bigger than the max pattern length */
    }
}

/**
 * @brief Bookmarks the to-be-replaced patterns for all nodes
 *
 * @param node
 * @return
 *****************************************************************************/
static unsigned int mf_repdata_bookreplacements (ACT_NODE_t *node)
{
    size_t i;
    unsigned int ret;

    ret = node_book_replacement (node);

    for (i = 0; i < node->outgoing_size; i++)
    {
        /* Recursively call itself to traverse all nodes */
        ret += mf_repdata_bookreplacements (node->outgoing[i].next);
    }

    return ret;
}

/**
 * @brief Resets the replacement data and prepares it for a new operation
 *
 * @param rd
 *****************************************************************************/
void mf_repdata_reset (MF_REPLACEMENT_DATA_t *rd)
{
    rd->buffer.length = 0;
    rd->backlog.length = 0;
    rd->curser = 0;
    rd->noms_size = 0;
}

/**
 * @brief Release the allocated resources to the replacement data
 *
 * @param rd
 *****************************************************************************/
void mf_repdata_release (MF_REPLACEMENT_DATA_t *rd)
{
    free((AC_ALPHABET_t *)rd->buffer.astring);
    free((AC_ALPHABET_t *)rd->backlog.astring);
    free(rd->noms);
}

/**
 * @brief Flushes out all the available stuff in the buffer to the user
 *
 * @param rd
 *****************************************************************************/
static void mf_repdata_flush (MF_REPLACEMENT_DATA_t *rd)
{
    rd->cbf(&rd->buffer, rd->user);
    rd->buffer.length = 0;
}

/**
 * @brief Extends the nominees array
 *
 * @param rd
 *****************************************************************************/
static void mf_repdata_grow_noms_array (MF_REPLACEMENT_DATA_t *rd)
{
    const size_t grow_factor = 128;

    if (rd->noms_capacity == 0)
    {
        rd->noms_capacity = grow_factor;
        rd->noms = (struct mf_replacement_nominee *) malloc
                (rd->noms_capacity * sizeof(struct mf_replacement_nominee));
        rd->noms_size = 0;
    }
    else
    {
        rd->noms_capacity += grow_factor;
        rd->noms = (struct mf_replacement_nominee *) realloc (rd->noms,
                                                              rd->noms_capacity * sizeof(struct mf_replacement_nominee));
    }
}

/**
 * @brief Adds the nominee to the end of the nominee list
 *
 * @param rd
 * @param new_nom
 *****************************************************************************/
static void mf_repdata_push_nominee
        (MF_REPLACEMENT_DATA_t *rd, struct mf_replacement_nominee *new_nom)
{
    struct mf_replacement_nominee *nomp;

    /* Extend the vector if needed */
    if (rd->noms_size == rd->noms_capacity)
        mf_repdata_grow_noms_array (rd);

    /* Add the new nominee to the end */
    nomp = &rd->noms[rd->noms_size];
    nomp->pattern = new_nom->pattern;
    nomp->position = new_nom->position;
    rd->noms_size ++;
}

/**
 * @brief Tries to add the nominee to the end of the nominee list
 *
 * @param rd
 * @param new_nom
 *****************************************************************************/
static void mf_repdata_booknominee (MF_REPLACEMENT_DATA_t *rd,
                                    struct mf_replacement_nominee *new_nom)
{
    struct mf_replacement_nominee *prev_nom;
    size_t prev_start_pos, prev_end_pos, new_start_pos;

    if (new_nom->pattern == NULL)
        return; /* This is not a to-be-replaced pattern; ignore it. */

    new_start_pos = new_nom->position - new_nom->pattern->ptext.length;

    switch (rd->replace_mode)
    {
        case MF_REPLACE_MODE_LAZY:

            if (new_start_pos < rd->curser)
                return; /* Ignore the new nominee, because it overlaps with the
                         * previous replacement */

            if (rd->noms_size > 0)
            {
                prev_nom = &rd->noms[rd->noms_size - 1];
                prev_end_pos = prev_nom->position;

                if (new_start_pos < prev_end_pos)
                    return;
            }
            break;

        case MF_REPLACE_MODE_DEFAULT:
        case MF_REPLACE_MODE_NORMAL:
        default:

            while (rd->noms_size > 0)
            {
                prev_nom = &rd->noms[rd->noms_size - 1];
                prev_start_pos =
                        prev_nom->position - prev_nom->pattern->ptext.length;
                prev_end_pos = prev_nom->position;

                if (new_start_pos <= prev_start_pos)
                    rd->noms_size--;    /* Remove that nominee, because it is a
                                         * factor of the new nominee */
                else
                    break;  /* Get out the loop and add the new nominee */
            }
            break;
    }

    mf_repdata_push_nominee(rd, new_nom);
}

/**
 * @brief Append the given text to the output buffer
 *
 * @param rd
 * @param text
 *****************************************************************************/
static void mf_repdata_appendtext (MF_REPLACEMENT_DATA_t *rd, AC_TEXT_t *text)
{
    size_t remaining_bufspace = 0;
    size_t remaining_text = 0;
    size_t copy_len = 0;
    size_t copy_index = 0;

    while (copy_index < text->length)
    {
        remaining_bufspace = MF_REPLACEMENT_BUFFER_SIZE - rd->buffer.length;
        remaining_text = text->length - copy_index;

        copy_len = (remaining_bufspace >= remaining_text)?
                   remaining_text : remaining_bufspace;

        memcpy((void *)&rd->buffer.astring[rd->buffer.length],
               (void *)&text->astring[copy_index],
               copy_len * sizeof(AC_ALPHABET_t));

        rd->buffer.length += copy_len;
        copy_index += copy_len;

        if (rd->buffer.length == MF_REPLACEMENT_BUFFER_SIZE)
            mf_repdata_flush(rd);
    }
}

/**
 * @brief Append a factor of the current text to the output buffer
 *
 * @param rd
 * @param from
 * @param to
 *****************************************************************************/
static void mf_repdata_appendfactor
        (MF_REPLACEMENT_DATA_t *rd, size_t from, size_t to)
{
    AC_TEXT_t *instr = rd->trie->text;
    AC_TEXT_t factor;
    size_t backlog_base_pos;
    size_t base_position = rd->trie->base_position;

    if (to < from)
        return;

    if (base_position <= from)
    {
        /* The backlog located in the input text part */
        factor.astring = &instr->astring[from - base_position];
        factor.length = to - from;
        mf_repdata_appendtext(rd, &factor);
    }
    else
    {
        backlog_base_pos = base_position - rd->backlog.length;
        if (from < backlog_base_pos)
            return; /* shouldn't come here */

        if (to < base_position)
        {
            /* The backlog located in the backlog part */
            factor.astring = &rd->backlog.astring[from - backlog_base_pos];
            factor.length = to - from;
            mf_repdata_appendtext (rd, &factor);
        }
        else
        {
            /* The factor is divided between backlog and input text */

            /* The backlog part */
            factor.astring = &rd->backlog.astring[from - backlog_base_pos];
            factor.length = rd->backlog.length - from + backlog_base_pos;
            mf_repdata_appendtext (rd, &factor);

            /* The input text part */
            factor.astring = instr->astring;
            factor.length = to - base_position;
            mf_repdata_appendtext (rd, &factor);
        }
    }
}

/**
 * @brief Saves the backlog part of the current text to the backlog buffer. The
 * backlog part is the part after @p bg_pos
 *
 * @param rd
 * @param bg_pos backlog position
 *****************************************************************************/
static void mf_repdata_savetobacklog (MF_REPLACEMENT_DATA_t *rd, size_t bg_pos)
{
    size_t bg_pos_r; /* relative backlog position */
    AC_TEXT_t *instr = rd->trie->text;
    size_t base_position = rd->trie->base_position;

    if (base_position < bg_pos)
        bg_pos_r = bg_pos - base_position;
    else
        bg_pos_r = 0; /* the whole input text must go to backlog */

    if (instr->length == bg_pos_r)
        return; /* Nothing left for the backlog */

    if (instr->length < bg_pos_r)
        return; /* unexpected : assert (instr->length >= bg_pos_r) */

    /* Copy the part after bg_pos_r to the backlog buffer */
    memcpy( (AC_ALPHABET_t *)
            &rd->backlog.astring[rd->backlog.length],
            &instr->astring[bg_pos_r],
            instr->length - bg_pos_r );

    rd->backlog.length += instr->length - bg_pos_r;
}

/**
 * @brief Perform replacement operations on the non-backlog part of the current
 * text. In-range nominees will be replaced the original pattern and the result
 * will be pushed to the output buffer.
 *
 * @param rd
 * @param to_position
 *****************************************************************************/
static void mf_repdata_do_replace
        (MF_REPLACEMENT_DATA_t *rd, size_t to_position)
{
    unsigned int index;
    struct mf_replacement_nominee *nom;
    size_t base_position = rd->trie->base_position;

    if (to_position < base_position)
        return;

    /* Replace the candidate patterns */
    if (rd->noms_size > 0)
    {
        for (index = 0; index < rd->noms_size; index++)
        {
            nom = &rd->noms[index];

            if (to_position <= (nom->position - nom->pattern->ptext.length))
                break;

            /* Append the space before pattern */
            mf_repdata_appendfactor (rd, rd->curser, /* from */
                                     nom->position - nom->pattern->ptext.length /* to */);

            /* Append the replacement instead of the pattern */
            mf_repdata_appendtext(rd, &nom->pattern->rtext);

            rd->curser = nom->position;
        }
        rd->noms_size -= index;

        /* Shift the array to the left to eliminate the consumed nominees */
        if (rd->noms_size && index)
        {
            memcpy (&rd->noms[0], &rd->noms[index],
                    rd->noms_size * sizeof(struct mf_replacement_nominee));
            /* TODO: implement a circular queue */
        }
    }

    /* Append the chunk between the last pattern and to_position */
    if (to_position > rd->curser)
    {
        mf_repdata_appendfactor (rd, rd->curser, to_position);

        rd->curser = to_position;
    }

    if (base_position <= rd->curser)
    {
        /* we consume the whole backlog or none of it */
        rd->backlog.length = 0;
    }
}

/**
 * @brief Replaces the patterns in the given text with their correspondence
 * replacement in the A.C. Trie
 *
 * @param thiz
 * @param instr
 * @param mode
 * @param callback
 * @param param
 * @return
 *****************************************************************************/
int multifast_replace (AC_TRIE_t *thiz, AC_TEXT_t *instr,
                       MF_REPLACE_MODE_t mode, MF_REPLACE_CALBACK_f callback, void *param)
{
    ACT_NODE_t *current;
    ACT_NODE_t *next;
    struct mf_replacement_nominee nom;
    MF_REPLACEMENT_DATA_t *rd = &thiz->repdata;

    size_t position_r = 0;  /* Relative current position in the input string */
    size_t backlog_pos = 0; /* Relative backlog position in the input string */

    if (thiz->trie_open)
        return -1; /* _finalize() must be called first */

    if (!rd->has_replacement)
        return -2; /* Trie doesn't have any to-be-replaced pattern */

    rd->cbf = callback;
    rd->user = param;
    rd->replace_mode = mode;

    thiz->text = instr; /* Save the input string in a helper variable
                         * for convenience */

    current = thiz->last_node;

    /* Main replace loop:
     * Find patterns and bookmark them
     */
    while (position_r < instr->length)
    {
        if (!(next = node_find_next_bs(current, instr->astring[position_r])))
        {
            /* Failed to follow a pattern */
            if(current->failure_node)
                current = current->failure_node;
            else
                position_r++;
        }
        else
        {
            current = next;
            position_r++;
        }

        if (current->final && next)
        {
            /* Bookmark nominee patterns for replacement */
            nom.pattern = current->to_be_replaced;
            nom.position = thiz->base_position + position_r;

            mf_repdata_booknominee (rd, &nom);
        }
    }

    /*
     * At the end of input chunk, if the tail of the chunk is a prefix of a
     * pattern, then we must keep it in the backlog buffer and wait for the
     * next chunk to decide about it. */

    backlog_pos = thiz->base_position + instr->length - current->depth;

    /* Now replace the patterns up to the backlog_pos point */
    mf_repdata_do_replace (rd, backlog_pos);

    /* Save the remaining to the backlog buffer */
    mf_repdata_savetobacklog (rd, backlog_pos);

    /* Save status variables */
    thiz->last_node = current;
    thiz->base_position += position_r;

    return 0;
}

/**
 * @brief Flushes the remaining data back to the user and ends the replacement
 * operation.
 *
 * @param thiz
 * @param keep Indicates the continuity of the chunks. 0 means that the last
 * chunk has been fed in, and we want to end the replacement and receive the
 * final result.
 *****************************************************************************/
void multifast_rep_flush (AC_TRIE_t *thiz, int keep)
{
    if (!keep)
    {
        mf_repdata_do_replace (&thiz->repdata, thiz->base_position);
    }

    mf_repdata_flush (&thiz->repdata);

    if (!keep)
    {
        mf_repdata_reset (&thiz->repdata);
        thiz->last_node = thiz->root;
        thiz->base_position = 0;
    }
}