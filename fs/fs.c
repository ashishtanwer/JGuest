#include <inc/string.h>
#include <inc/sha1.h>
#include "fs.h"
#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

/* Function prototypes */
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

/*  
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;
}

/*  
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array within the SHA1Context provided
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *
 *  Returns:
 *      1 if successful, 0 if it failed.
 *
 *  Comments:
 *
 */
int SHA1Result(SHA1Context *context)
{

    if (context->Corrupted)
    {
        return 0;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }

    return 1;
}

/*  
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion of
 *      the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA-1 context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of the
 *          message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Input(     SHA1Context         *context,
                    const unsigned char *message_array,
                    unsigned            length)
{
    if (!length)
    {
        return;
    }

    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }

    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
                                                (*message_array & 0xFF);

        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            /* Force it to 32 bits */
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }
}

/*  
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      Many of the variable names in the SHAContext, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *         
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */      
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int         t;                  /* Loop counter                 */
    unsigned    temp;               /* Temporary word value         */
    unsigned    W[80];              /* Word sequence                */
    unsigned    A, B, C, D, E;      /* Word buffers                 */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Message_Digest[0] =
                        (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] =
                        (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] =
                        (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] =
                        (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] =
                        (context->Message_Digest[4] + E) & 0xFFFFFFFF;

    context->Message_Block_Index = 0;
}

/*  
 *  SHA1PadMessage
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call SHA1ProcessMessageBlock()
 *      appropriately.  When it returns, it can be assumed that the
 *      message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;

    SHA1ProcessMessageBlock(context);
}
struct list *hash_list;

// --------------------------------------------------------------
// Super block
// --------------------------------------------------------------

// Validate the file system super-block.
    void
check_super(void)
{
    if (super->s_magic != FS_MAGIC)
        panic("bad file system magic number");

    if (super->s_nblocks > DISKSIZE/BLKSIZE)
        panic("file system is too large");

    cprintf("superblock is good\n");
}

// --------------------------------------------------------------
// Free block bitmap
// --------------------------------------------------------------

// Check to see if the block bitmap indicates that block 'blockno' is free.
// Return 1 if the block is free, 0 if not.
    bool
block_is_free(uint32_t blockno)
{
    if (super == 0 || blockno >= super->s_nblocks)
        return 0;
    if (bitmap[blockno / 32] & (1 << (blockno % 32)))
        return 1;
    return 0;
}

// Mark a block free in the bitmap
    void
free_block(uint32_t blockno)
{
    // Blockno zero is the null pointer of block numbers.
    if (blockno == 0)
        panic("attempt to free zero block");
    bitmap[blockno/32] |= 1<<(blockno%32);
}

// Search the bitmap for a free block and allocate it.  When you
// allocate a block, immediately flush the changed bitmap block
// to disk.
//
// Return block number allocated on success,
// -E_NO_DISK if we are out of blocks.
//
// Hint: use free_block as an example for manipulating the bitmap.
    int
alloc_block(void)
{
    // The bitmap consists of one or more blocks.  A single bitmap block
    // contains the in-use bits for BLKBITSIZE blocks.  There are
    // super->s_nblocks blocks in the disk altogether.

    // Ashish
	size_t i,j;
        for (i = 0; i < super->s_nblocks/32; i++) {
                for (j = 0; j < 32; j++) {
                        if ((bitmap[i] >> j) & 0x01) {
                                bitmap[i] &= ~(1 << j);
                                flush_block(bitmap + i);
                                return ((i * 32) + j);
                        }
                }
        }
    return -E_NO_DISK;
}

// Validate the file system bitmap.
//
// Check that all reserved blocks -- 0, 1, and the bitmap blocks themselves --
// are all marked as in-use.
    void
check_bitmap(void)
{
    uint32_t i;

    // Make sure all bitmap blocks are marked in-use
    for (i = 0; i * BLKBITSIZE < super->s_nblocks; i++)
        assert(!block_is_free(2+i));

    // Make sure the reserved and root blocks are marked in-use.
    assert(!block_is_free(0));
    assert(!block_is_free(1));

	cprintf("bitmap is good. total bitmap blocks = %d   super->s_nblocks=%d\n", i, super->s_nblocks);
}

//---------------------------------------------------------------
// Copy-on-write bitmap
//---------------------------------------------------------------

// Check to see if the COW bitmap indicates that block has >1 references
// Return 1 if the disk block is referred by multiple file blocks
bool
block_is_cow(uint32_t blockno)
{
        if (super == 0 || blockno >= super->s_nblocks)
                return 0;
        if (cow_bitmap[blockno / 32] & (1 << (blockno % 32)))
                return 1;
        return 0;
}
// Unmark a COW'ed block in the bitmap
void
mark_block_cow(uint32_t blockno)
{
        cow_bitmap[blockno/32] |= 1<<(blockno%32);
        flush_block(cow_bitmap + blockno/32);
}
// Mark a particular block as copy-on-write, immediately flush 
// the changed bitmap block to disk.
void
unmark_block_cow(uint32_t blockno)
{
	cow_bitmap[blockno/32] &= ~(1<<(blockno%32));
        flush_block(cow_bitmap + blockno/32);
}
// Find which all blocks are COW. Print them.
void find_cow_blocks()
{
	int i;
//	mark_block_cow(1);	
//	mark_block_cow(35);
//	unmark_block_cow(1);
	cprintf("COW Blocks:\n");
	for (i = 0; i < super->s_nblocks; i++)
                if (block_is_cow(i))
			cprintf(" %d",i);
	cprintf("\n");
}
// --------------------------------------------------------------
// File system structures
// --------------------------------------------------------------

// Initialize the file system
    void
fs_init(void)
{
    static_assert(sizeof(struct File) == 256);

#ifndef VMM_GUEST
    // Find a JOS disk.  Use the second IDE disk (number 1) if available.
    if (ide_probe_disk1())
        ide_set_disk(1);
    else
        ide_set_disk(0);
#else
    host_ipc_init();
#endif
    bc_init();

    // Set "super" to point to the super block.
    super = diskaddr(1);
    // Set "bitmap" to the beginning of the first bitmap block.
    bitmap = diskaddr(2);

    check_super();
    check_bitmap();
}

// Find the disk block number slot for the 'filebno'th block in file 'f'.
// Set '*ppdiskbno' to point to that slot.
// The slot will be one of the f->f_direct[] entries,
// or an entry in the indirect block.
// When 'alloc' is set, this function will allocate an indirect block
// if necessary.
//
// Returns:
//	0 on success (but note that *ppdiskbno might equal 0).
//	-E_NOT_FOUND if the function needed to allocate an indirect block, but
//		alloc was 0.
//	-E_NO_DISK if there's no space on the disk for an indirect block.
//	-E_INVAL if filebno is out of range (it's >= NDIRECT + NINDIRECT).
//
// Analogy: This is like pgdir_walk for files.
// Hint: Don't forget to clear any block you allocate.
    static int
file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)
{
    // Ashish.
	int i;

	if (filebno >= NDIRECT + NINDIRECT)
		return -E_INVAL;

	if (filebno < NDIRECT) {
		*ppdiskbno = &(f->f_direct[filebno]);
		return 0;
	}
	else {
		if (!f->f_indirect) {
			if (alloc) {
				int r  = alloc_block();

				if (r < 0)
					return r;

				f->f_indirect = r;
			}
			else
				return -E_NOT_FOUND;
		}

		uint32_t *addr = (uint32_t*)diskaddr(f->f_indirect);//(uint32_t*)(uint64_t)((f->f_indirect*BLKSIZE)+DISKMAP);
		*ppdiskbno = &(addr[filebno-NDIRECT]);
		return 0;
	}
    panic("file_block_walk not implemented");
}

// Set *blk to the address in memory where the filebno'th
// block of file 'f' would be mapped.
// Allocate the block if it doesn't yet exist.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_NO_DISK if a block needed to be allocated but the disk is full.
//	-E_INVAL if filebno is out of range.
//
// Hint: Use file_block_walk and alloc_block.
int
file_get_block(struct File *f, uint32_t filebno, char **blk)
{
	// Ashish

	int r;
	uint32_t *ppdiskbno;
	if ((r = file_block_walk(f, filebno, &ppdiskbno, true)) < 0)
		return r;
	if (*ppdiskbno == 0) {
		uint32_t blknum = alloc_block();
		if (blknum < 0)
			return -E_NO_DISK;
		*ppdiskbno = blknum;
	}

//	*blk = (char*) (uint64_t)((*ppdiskbno * BLKSIZE) + DISKMAP);
	*blk = (char*)diskaddr(*ppdiskbno);
//	cprintf("read blk=%d", *ppdiskbno);
	return 0;

	panic("file_get_block not implemented");
}

int64_t get_num_allocated_blocks()
{
 //       cprintf("BLKBITSIZE=%d BLKSECTS=%d\n",BLKBITSIZE,BLKSECTS);
        size_t i,j;
	uint64_t allocated_blocks=0;
        for (i = 0; i < super->s_nblocks/32; i++)
                for (j = 0; j < 32; j++)
                        if (!((bitmap[i] >> j) & 0x01)) allocated_blocks++;

	return allocated_blocks;
}
void
check_block_info(void)
{
        int i;

        cprintf("\n=========================Block Information Begin=====================");
        cprintf("\n Total allocated block: %d\n", get_num_allocated_blocks());
        cprintf("\nblock_no   ref_count   COW\n");
        for (i = 0; i < 100; i++) {
                if(hash_list[i].hash != 0) {
                        cprintf("%d        %d           %d",
                                 hash_list[i].blknum, hash_list[i].refcount, block_is_cow(hash_list[i].blknum));
                        cprintf("\n");
                }

        }
        cprintf("=========================Block Information End======================\n");

}
struct list* getBlknumFromHash(uint64_t hash)
{
	int i;
	for (i=0; i<100; i++)
	{
		if (hash_list[i].hash == hash)
			return &hash_list[i];
	}
	return NULL;
}
struct list* get_block_struct_from_block(uint32_t blknum)
{
        int i;
        for (i=0; i<100; i++)
        {
		if (hash_list[i].blknum == blknum)
			return &hash_list[i];
	}
	return NULL;
}
void append_hash_list(uint64_t hash, uint64_t blknum)
{
	int i;
        for (i=0; i<100; i++)
        {
		if (hash_list[i].hash == 0)
			break;
	}

	if (i == 100)
		panic("error : Cannot create more hashes. List if full\n");

        hash_list[i].hash = hash;
        hash_list[i].blknum = blknum;
        hash_list[i].refcount = 0;

	flush_block(hash_list);// + (head*sizeof(struct list)/BLKSIZE)); //TODO: What if the structure lies on the boundry of two blocks? In that case
								     // we need to flush two blocks.
}

// Try to find a file named "name" in dir.  If so, set *file to it.
//
// Returns 0 and sets *file on success, < 0 on error.  Errors are:
//	-E_NOT_FOUND if the file is not found
    static int
dir_lookup(struct File *dir, const char *name, struct File **file)
{
    int r;
    uint32_t i, j, nblock;
    char *blk;
    struct File *f;

    // Search dir for name.
    // We maintain the invariant that the size of a directory-file
    // is always a multiple of the file system's block size.
    assert((dir->f_size % BLKSIZE) == 0);
    nblock = dir->f_size / BLKSIZE;
    for (i = 0; i < nblock; i++) {
        if ((r = file_get_block(dir, i, &blk)) < 0)
            return r;
        f = (struct File*) blk;
		for (j = 0; j < BLKFILES; j++) {
            if (strcmp(f[j].f_name, name) == 0) {
                *file = &f[j];
                return 0;
			}
            }
    }
    return -E_NOT_FOUND;
}

// Set *file to point at a free File structure in dir.  The caller is
// responsible for filling in the File fields.
    static int
dir_alloc_file(struct File *dir, struct File **file)
{
    int r;
    uint32_t nblock, i, j;
    char *blk;
    struct File *f;

    assert((dir->f_size % BLKSIZE) == 0);
    nblock = dir->f_size / BLKSIZE;
    for (i = 0; i < nblock; i++) {
        if ((r = file_get_block(dir, i, &blk)) < 0)
            return r;
        f = (struct File*) blk;
        for (j = 0; j < BLKFILES; j++)
            if (f[j].f_name[0] == '\0') {
                *file = &f[j];
                return 0;
            }
    }
    dir->f_size += BLKSIZE;
    if ((r = file_get_block(dir, i, &blk)) < 0)
        return r;
    f = (struct File*) blk;
    *file = &f[0];
    return 0;
}

// Skip over slashes.
    static const char*
skip_slash(const char *p)
{
    while (*p == '/')
        p++;
    return p;
}

// Evaluate a path name, starting at the root.
// On success, set *pf to the file we found
// and set *pdir to the directory the file is in.
// If we cannot find the file but find the directory
// it should be in, set *pdir and copy the final path
// element into lastelem.
    static int
walk_path(const char *path, struct File **pdir, struct File **pf, char *lastelem)
{
    const char *p;
    char name[MAXNAMELEN];
    struct File *dir, *f;
    int r;

    // if (*path != '/')
    //	return -E_BAD_PATH;
    path = skip_slash(path);
    f = &super->s_root;
    dir = 0;
    name[0] = 0;

    if (pdir)
        *pdir = 0;
    *pf = 0;
    while (*path != '\0') {
        dir = f;
        p = path;
        while (*path != '/' && *path != '\0')
            path++;
        if (path - p >= MAXNAMELEN)
            return -E_BAD_PATH;
        memmove(name, p, path - p);
        name[path - p] = '\0';
        path = skip_slash(path);

        if (dir->f_type != FTYPE_DIR)
            return -E_NOT_FOUND;

        if ((r = dir_lookup(dir, name, &f)) < 0) {
            if (r == -E_NOT_FOUND && *path == '\0') {
                if (pdir)
                    *pdir = dir;
                if (lastelem)
                    strcpy(lastelem, name);
                *pf = 0;
            }
            return r;
        }
    }

    if (pdir)
        *pdir = dir;
    *pf = f;
    return 0;
}

// --------------------------------------------------------------
// File operations
// --------------------------------------------------------------

// Create "path".  On success set *pf to point at the file and return 0.
// On error return < 0.
    int
file_create(const char *path, struct File **pf)
{
    char name[MAXNAMELEN];
    int r;
    struct File *dir, *f;

    if ((r = walk_path(path, &dir, &f, name)) == 0)
        return -E_FILE_EXISTS;
    if (r != -E_NOT_FOUND || dir == 0)
        return r;
    if ((r = dir_alloc_file(dir, &f)) < 0)
        return r;
    strcpy(f->f_name, name);
    *pf = f;
    file_flush(dir);
    return 0;
}

// Open "path".  On success set *pf to point at the file and return 0.
// On error return < 0.
    int
file_open(const char *path, struct File **pf)
{
    return walk_path(path, 0, pf, 0);
}

// Read count bytes from f into buf, starting from seek position
// offset.  This meant to mimic the standard pread function.
// Returns the number of bytes read, < 0 on error.
    ssize_t
file_read(struct File *f, void *buf, size_t count, off_t offset)
{
    int r, bn;
    off_t pos;
    char *blk;

    if (offset >= f->f_size)
        return 0;

    count = MIN(count, f->f_size - offset);

    for (pos = offset; pos < offset + count; ) {
        if ((r = file_get_block(f, pos / BLKSIZE, &blk)) < 0)
            return r;
        bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
        memmove(buf, blk + pos % BLKSIZE, bn);
        pos += bn;
        buf += bn;
    }

    return count;
}

uint64_t calculate_hash(const char *buf, size_t count)
{
	int i;
	uint64_t *hash=0;
	SHA1Context sha;

	SHA1Reset(&sha);

	SHA1Input(&sha, (const unsigned char *)buf, count);

	if(SHA1Result(&sha))
	{
//		cprintf("SHA OUTPUT: %08x\n", sha.Message_Digest[0]);
		return sha.Message_Digest[0];
	}
	else
		panic("Failed to generate SHA\n");
	
	//hash = (uint64_t *)(uint64_t)md5(buf, (int)count);
	//if (hash != 0)
	//	return *hash;
/*
	for (i=0; i<count; i++)
	{
		hash += buf[i];
	}
*/
	return 0;
}

void increment_block_ref_count(struct list *hl)
{
	cprintf("Incrementing ref count for block=%d. currefcount=%d\n",hl->blknum, hl->refcount);
	hl->refcount++;
	flush_block(hash_list);// TODO: handle which block to flush. currently flushing 0th block + (head*sizeof(struct list)/BLKSIZE));
}

void remove_from_hash_list(struct list *hl)
{
	hl->hash = 0;
	hl->refcount = 0;
	hl->blknum = 0;
	flush_block(hash_list);
}
void decrement_block_ref_count(struct list *hl)
{
	//TODO: assert of ref count is already 0
	hl->refcount--;
	cprintf("Decrementing ref count for block=%d. currefcount=%d\n",hl->blknum, hl->refcount);
	if (hl->refcount == 0) {
		cprintf("Freeing block %d. Unmarking cow too.\n", hl->blknum);
		free_block(hl->blknum);
		unmark_block_cow(hl->blknum);
		hl->hash = 0;
		//check_block_info();
		//TODO: Mark *ppdiskbno to 0
	}
	else if (hl->refcount == 1) {
		cprintf("Unmarking cow block %d\n", hl->blknum);
		unmark_block_cow(hl->blknum);
	}
	flush_block(hash_list);
}
char temp_block_bytes[BLKSIZE];
// Write count bytes from buf into f, starting at seek position
// offset.  This is meant to mimic the standard pwrite function.
// Extends the file if necessary.
// Returns the number of bytes written, < 0 on error.
int
file_write(struct File *f, const void *buf, size_t count, off_t offset)
{
    //Ashish
	int r, bn;
	off_t pos;
	char *blk;

	// Extend file if necessary
	if (offset + count > f->f_size)
		if ((r = file_set_size(f, offset + count)) < 0)
			return r;

/*	for (pos = offset; pos < offset + count; ) {
		cprintf("In file_write, filebno=%d\n", pos / BLKSIZE);
		uint64_t hash = calculate_hash((const char*)buf, count); //TODO: What if writes aren't multiple of 4096. Also this should not pass count.
		if ((r = custom_file_get_block(f, pos / BLKSIZE, &blk, hash)) < 0)
			return r;
		bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
		memmove(blk + pos % BLKSIZE, buf, bn);
		pos += bn;
		buf += bn;
	}*/

	for (pos = offset; pos < offset + count; ) {
		int r;
		uint32_t filebno;
		uint32_t *ppdiskbno;
		char *blk;

		filebno = pos / BLKSIZE;
		if ((r = file_block_walk(f, filebno, &ppdiskbno, true)) < 0)
                	return r;

		if (*ppdiskbno != 0) {
			if (block_is_cow(*ppdiskbno)) {
#ifndef POST_PROCESS_DEDUP
				blk = (char*)diskaddr(*ppdiskbno);
				bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
				memcpy(temp_block_bytes, blk, BLKSIZE);
				memcpy(temp_block_bytes + pos % BLKSIZE, buf, bn);
				uint64_t hash = calculate_hash((const char*)temp_block_bytes, BLKSIZE);
				struct list *dup_blk = getBlknumFromHash(hash);
				if (dup_blk  != NULL) {
					increment_block_ref_count(dup_blk);
					mark_block_cow(dup_blk->blknum);
					decrement_block_ref_count(get_block_struct_from_block(*ppdiskbno));
					cprintf("Write of %c was received in a cow block %d, re-writing resulted in a new dup block %d\n", ((char*)buf)[0],*ppdiskbno, dup_blk->blknum);
					*ppdiskbno = dup_blk->blknum;

			                pos += bn;
                			buf += bn;
					continue;
				}
				else
#endif
				{
					//TODO:decrement ref count of *ppdiskbno block struct
					decrement_block_ref_count(get_block_struct_from_block(*ppdiskbno));
					*ppdiskbno = 0;
					cprintf("Write was received in a cow block %d, new block creation required\n", *ppdiskbno);
				}
			}
			else { //no cow
				cprintf("Block is not a cow block, write %c normally in block %d\n",((char*)buf)[0],*ppdiskbno);
#ifndef POST_PROCESS_DEDUP
                        	bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
                        	memset(temp_block_bytes, '\0', BLKSIZE);
                        	memcpy(temp_block_bytes + pos % BLKSIZE, buf, bn);
                        	uint64_t hash = calculate_hash(temp_block_bytes, BLKSIZE);
                       	 	struct list *dup_blk = getBlknumFromHash(hash);
                        	if (dup_blk  != NULL) {
                                	char *temp = (char*)buf;
	                                cprintf("Writing on a non-cow block for %c resulted in a dup block of %d\n", temp[0], dup_blk->blknum);
                	                //TODO:increment ref count of dup_blk
					increment_block_ref_count(dup_blk);
                        	        mark_block_cow(dup_blk->blknum);
					//TODO: decrement ref count to the original block
					decrement_block_ref_count(get_block_struct_from_block(*ppdiskbno));
        	                        *ppdiskbno = dup_blk->blknum;
					pos += bn;
                                        buf += bn;
					continue;
                       		}
#else
				remove_from_hash_list(get_block_struct_from_block(*ppdiskbno));
#endif
			}
		}
		
		if (*ppdiskbno == 0) {
#ifndef POST_PROCESS_DEDUP
			bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
			memset(temp_block_bytes, '\0', BLKSIZE);
			memcpy(temp_block_bytes + pos % BLKSIZE, buf, bn);
			uint64_t hash = calculate_hash(temp_block_bytes, BLKSIZE);
			struct list *dup_blk = getBlknumFromHash(hash);
			if (dup_blk  != NULL) {
				char *temp = (char*)buf;
				cprintf("Creation of new block for %c resulted in a dup block of %d\n", temp[0], dup_blk->blknum);
				*ppdiskbno = dup_blk->blknum;
				//TODO:increment ref count of dup_blk
				increment_block_ref_count(dup_blk);
				mark_block_cow(dup_blk->blknum);
			}
			else 
#endif
{
			     	uint32_t blknum = alloc_block();
                        	if (blknum < 0)
                                	return -E_NO_DISK;
                        	*ppdiskbno = blknum;
#ifndef POST_PROCESS_DEDUP

                        	append_hash_list(hash, blknum);
				increment_block_ref_count(get_block_struct_from_block(blknum));
#endif

				cprintf("Created a fresh new block %d for %c\n",blknum, ((char*)buf)[0]);
			}
		}

		blk = (char*)diskaddr(*ppdiskbno);
                bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
                memmove(blk + pos % BLKSIZE, buf, bn);
                pos += bn;
                buf += bn;
	}

	return count;
}


// Remove a block from file f.  If it's not there, just silently succeed.
// Returns 0 on success, < 0 on error.
    static int
file_free_block(struct File *f, uint32_t filebno)
{
    int r;
    uint32_t *ptr;

    if ((r = file_block_walk(f, filebno, &ptr, 0)) < 0)
        return r;
    if (*ptr) {
        free_block(*ptr);
        *ptr = 0;
    }
    return 0;
}

// Remove any blocks currently used by file 'f',
// but not necessary for a file of size 'newsize'.
// For both the old and new sizes, figure out the number of blocks required,
// and then clear the blocks from new_nblocks to old_nblocks.
// If the new_nblocks is no more than NDIRECT, and the indirect block has
// been allocated (f->f_indirect != 0), then free the indirect block too.
// (Remember to clear the f->f_indirect pointer so you'll know
// whether it's valid!)
// Do not change f->f_size.
    static void
file_truncate_blocks(struct File *f, off_t newsize)
{
    int r;
    uint32_t bno, old_nblocks, new_nblocks;

    old_nblocks = (f->f_size + BLKSIZE - 1) / BLKSIZE;
    new_nblocks = (newsize + BLKSIZE - 1) / BLKSIZE;
    for (bno = new_nblocks; bno < old_nblocks; bno++)
        if ((r = file_free_block(f, bno)) < 0)
            cprintf("warning: file_free_block: %e", r);

    if (new_nblocks <= NDIRECT && f->f_indirect) {
        free_block(f->f_indirect);
        f->f_indirect = 0;
    }
}

// Set the size of file f, truncating or extending as necessary.
    int
file_set_size(struct File *f, off_t newsize)
{
    if (f->f_size > newsize)
        file_truncate_blocks(f, newsize);
    f->f_size = newsize;
    flush_block(f);
    return 0;
}

// Flush the contents and metadata of file f out to disk.
// Loop over all the blocks in file.
// Translate the file block number into a disk block number
// and then check whether that disk block is dirty.  If so, write it out.
    void
file_flush(struct File *f)
{
    int i;
    uint32_t *pdiskbno;

    for (i = 0; i < (f->f_size + BLKSIZE - 1) / BLKSIZE; i++) {
        if (file_block_walk(f, i, &pdiskbno, 0) < 0 ||
                pdiskbno == NULL || *pdiskbno == 0)
            continue;
        flush_block(diskaddr(*pdiskbno));
    }
    flush_block(f);
    if (f->f_indirect)
        flush_block(diskaddr(f->f_indirect));
}

// Remove a file by truncating it and then zeroing the name.
    int
file_remove(const char *path)
{
    int r;
    struct File *f;

    if ((r = walk_path(path, 0, &f, 0)) < 0)
        return r;

    file_truncate_blocks(f, 0);
    f->f_name[0] = '\0';
    f->f_size = 0;
    flush_block(f);

    return 0;
}

// Sync the entire file system.  A big hammer.
    void
fs_sync(void)
{
    int i;
    for (i = 1; i < super->s_nblocks; i++)
        flush_block(diskaddr(i));
}

