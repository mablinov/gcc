#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* For pthread_jit_write_protect_np */
#include <pthread.h>

void *allocate_trampoline_page (void);
int get_trampolines_per_page (void);
struct tramp_ctrl_data *allocate_tramp_ctrl (struct tramp_ctrl_data *parent);
void *allocate_trampoline_page (void);

void __builtin_nested_func_ptr_created (void *chain, void *func, void **dst);
void __builtin_nested_func_ptr_deleted (void);

struct tramp_ctrl_data;
struct tramp_ctrl_data
{
  struct tramp_ctrl_data *prev;

  int free_trampolines;

  /* This will be pointing to an executable mmap'ed page.  */
  struct aarch64_trampoline *trampolines;
};

static const uint8_t trampoline_insns[] = {
  /* movabs $<chain>,%r11  */
  0x49, 0xbb,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  /* movabs $<func>,%r10  */
  0x49, 0xba,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  /* rex.WB jmpq *%r11  */
  0x41, 0xff, 0xe3
};

union ix86_trampoline {
  uint8_t insns[sizeof(trampoline_insns)];

  struct fields {
    uint8_t insn_0[2];
    void *chain_ptr;
    uint8_t insn_1[2];
    void *func_ptr;
    uint8_t insn_2[3];
  } fields;
};

int
get_trampolines_per_page (void)
{
  return getpagesize() / sizeof(struct ix86_trampoline);
}

static _Thread_local struct tramp_ctrl_data *tramp_ctrl_curr = NULL;

void *
allocate_trampoline_page (void)
{
  void *page;

  page = mmap (0, getpagesize (), PROT_WRITE | PROT_EXEC,
	       MAP_ANON | MAP_PRIVATE, 0, 0);

  return page;
}

struct tramp_ctrl_data *
allocate_tramp_ctrl (struct tramp_ctrl_data *parent)
{
  struct tramp_ctrl_data *p = malloc (sizeof (struct tramp_ctrl_data));
  if (p == NULL)
    return NULL;

  p->trampolines = allocate_trampoline_page ();

  if (p->trampolines == MAP_FAILED)
    return NULL;

  p->prev = parent;
  p->free_trampolines = get_trampolines_per_page();

  return p;
}

void
__builtin_nested_func_ptr_created (void *chain, void *func, void **dst)
{
  if (tramp_ctrl_curr == NULL)
    {
      tramp_ctrl_curr = allocate_tramp_ctrl (NULL);
      if (tramp_ctrl_curr == NULL)
	abort ();
    }

  /* TODO: Eventually, this check needs to trigger the allocation of another
     page of memory, and then somehow link that new page in with the previous
     pages.  */
  if (tramp_ctrl_curr->free_trampolines == 0)
    {
      /* Allocate new tramp_ctrl, set new->prev to current_ptr, set current_ptr to new
	 page.  */
      void *tramp_ctrl = allocate_tramp_ctrl (tramp_ctrl_curr);
      if (!tramp_ctrl)
	abort ();

      tramp_ctrl_curr = tramp_ctrl;
    }

  union ix86_trampoline *trampoline
    = &tramp_ctrl_curr->trampolines[get_trampolines_per_page ()
				    - tramp_ctrl_curr->free_trampolines];

  /* Generate code for the trampoline, filling in those bits as required from
     the data passed into this function.  */

  memcpy (trampoline->insns, ix86_trampoline_insns,
	  sizeof(ix86_trampoline_insns));
  trampoline->fields.func_ptr = func;
  trampoline->fields.chain_ptr = chain;

  tramp_ctrl_curr->free_trampolines -= 1;

  /* 2. Flush the i-cache for the code we just wrote.  We're going to also write
     some data onto this page, but we don't need to flush the icache for
     that.*/

  __builtin___clear_cache ((void *)trampoline->insns,
			   ((void *)trampoline->insns + sizeof(trampoline->insns)));

  /* 4. Return a pointer to the new trampoline.  */
  *dst = &trampoline->insns;
}

void
__builtin_nested_func_ptr_deleted (void)
{
  /* If the control structure is not initialised then surely there should be no
     trampolines allocated.  So, why did we end up here at all?  */
  if (tramp_ctrl_curr == NULL)
    abort ();		/* Maybe we should do something better.  */

  tramp_ctrl_curr->free_trampolines += 1;

  if (tramp_ctrl_curr->free_trampolines == get_trampolines_per_page ())
    {
      if (tramp_ctrl_curr->prev == NULL)
	{
	  /* We're the root tramp_ctrl; do nothing.  */
	  return;
	}

      munmap (tramp_ctrl_curr->trampolines, getpagesize());
      struct tramp_ctrl_data *prev = tramp_ctrl_curr->prev;
      free (tramp_ctrl_curr);
      tramp_ctrl_curr = prev;
    }
}
