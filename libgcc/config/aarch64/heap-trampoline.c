#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void __builtin_nested_func_ptr_created (void *sp, void *chain, void *func, void **dst);
void __builtin_nested_func_ptr_deleted (void *sp, void *chain, void *func, void **dst);

struct tramps_ctrl_data
{
  void *start_of_first_page;
  void *current_ptr;
};

static _Thread_local struct tramps_ctrl_data *tramps_ctrl = NULL;

static struct tramps_ctrl_data *
tramps_init_ctrl_data (void)
{
  int page_size;

  /* TODO: We are leaking memory on failure here.  */

  struct tramps_ctrl_data *p = malloc (sizeof (struct tramps_ctrl_data));
  if (p == NULL)
    return NULL;
  memset (p, 0, sizeof (struct tramps_ctrl_data));

  /* Allocate the first page.  */
  page_size = getpagesize ();
  p->start_of_first_page = mmap (0, page_size, PROT_WRITE | PROT_EXEC,
				 MAP_ANON | MAP_PRIVATE, 0, 0);
  if (p->start_of_first_page == MAP_FAILED)
    return NULL;

  p->current_ptr = p->start_of_first_page;

  return p;
}

/* Size of a single trampoline entry, in bytes.  */
#define SIZE_OF_TRAMPOLINE 64

static const uint32_t aarch64_trampoline_insns[] = {
  0xd503245f, /* hint    34 */
  0x580000b1, /* ldr     x17, .+20 */
  0x580000d2, /* ldr     x18, .+24 */
  0xd61f0220, /* br      x17 */
  0xd5033f9f, /* dsb     sy */
  0xd5033fdf /* isb */
};

struct aarch64_trampoline {
  uint32_t insns[6];
  void *func_ptr;
  void *chain_ptr;
};

void
__builtin_nested_func_ptr_created (void *sp, void *chain, void *func, void **dst)
{
  uintptr_t ptr, addr, start, end;
  int page_size;

  if (tramps_ctrl == NULL)
    tramps_ctrl = tramps_init_ctrl_data ();
  if (tramps_ctrl == NULL)
    abort ();	/* TODO: Something better?  */

  /* Figure out the start, and then the end, of the page currently being written
     too.  */
  page_size = getpagesize ();
  ptr = (uintptr_t) tramps_ctrl->current_ptr;
  start = ptr & ~(page_size - 1);
  end = start + page_size;
  printf ("Current trampoline page, start = %p, end = %p\n",
	  ((void *) start), ((void *) end));

  /* TODO: Eventually, this check needs to trigger the allocation of another
     page of memory, and then somehow link that new page in with the previous
     pages.  */
  if (ptr + SIZE_OF_TRAMPOLINE >= end)
    abort ();

  /* Generate code for the trampoline, filling in those bits as required from
     the data passed into this function.  */

  struct aarch64_trampoline *trampoline = (struct aarch64_trampoline *)ptr;
  memcpy (trampoline->insns, aarch64_trampoline_insns,
	  sizeof(aarch64_trampoline_insns));
  trampoline->func_ptr = func;
  trampoline->chain_ptr = chain;

  /* 2. Flush the i-cache for the code we just wrote.  We're going to also write
     some data onto this page, but we don't need to flush the icache for
     that.*/
  __builtin___clear_cache (tramps_ctrl->current_ptr, ptr);

  /* 3. Write out the information into a header block so we can understand what
     this trampoline represents.  */
#if 0
  ptr += 24;	/* Leave a gap.  */
  *((void **) ptr) = (void *) chain;
  ptr += 8;
  *((void **) ptr) = (void *) func;
  ptr += 8;
#endif

  /* 4. Return a pointer to the new trampoline.  */
  *dst = tramps_ctrl->current_ptr;
  tramps_ctrl->current_ptr = ptr;


  printf ("GCC: Generating a nested function pointer\n");
  printf ("     sp = %p, chain = %p, func = %p, dst = %p\n", sp, chain, func, dst);
  printf ("     ctrl = %p\n", tramps_ctrl);
  printf ("     tramp = %p\n", tramps_ctrl->current_ptr);
}

void
__builtin_nested_func_ptr_deleted (void *sp, void *chain, void *func, void **dst)
{
  uintptr_t ptr, addr, start, end;
  int page_size;

  /* If the control structure is not initialised then surely there should be no
     trampolines allocated.  So, why did we end up here at all?  */
  if (tramps_ctrl == NULL)
    abort ();		/* Maybe we should do something better.  */

  /* Figure out the start, and then the end, of the page currently being written
     too.  */
  page_size = getpagesize ();
  ptr = (uintptr_t) tramps_ctrl->current_ptr;
  start = ptr & ~(page_size - 1);
  end = start + page_size;
  printf ("Current trampoline page, start = %p, end = %p\n",
	  ((void *) start), ((void *) end));

  void *tramp = *dst;
  printf ("GCC: Deleting a nested function pointer\n");
  printf ("     sp = %p, chain = %p, func = %p, tramp = %p\n", sp, chain, func, tramp);
  printf ("     ctrl = %p\n", tramps_ctrl);
}
