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

struct aarch64_trampoline {
  uint32_t insns[6];
  void *func_ptr;
  void *chain_ptr;
};

int
get_trampolines_per_page (void)
{
  return getpagesize() / sizeof(struct aarch64_trampoline);
}

static _Thread_local struct tramp_ctrl_data *tramp_ctrl_curr = NULL;

struct tramp_ctrl_data *
allocate_tramp_ctrl (struct tramp_ctrl_data *parent)
{
  /* TODO: We are leaking memory on failure here.  */
  struct tramp_ctrl_data *p = malloc (sizeof (struct tramp_ctrl_data));
  if (p == NULL)
    return NULL;

  memset (p, 0, sizeof (struct tramp_ctrl_data));

  /* Allocate the corresponding page.  */
  p->trampolines = mmap (0, getpagesize (), PROT_WRITE | PROT_EXEC,
			 MAP_ANON | MAP_PRIVATE | MAP_JIT, 0, 0);
  if (p->trampolines == MAP_FAILED)
    return NULL;

  p->prev = parent;
  p->free_trampolines = get_trampolines_per_page();

  return p;
}

void *
allocate_trampoline_page (void)
{
  void *page;

  /* Allocate the first page.  */
  page = mmap (0, getpagesize (), PROT_WRITE | PROT_EXEC,
	       MAP_ANON | MAP_PRIVATE | MAP_JIT, 0, 0);

  if (page == MAP_FAILED)
    abort ();

  return page;
}

#if defined(__gnu_linux__)
static const uint32_t aarch64_trampoline_insns[] = {
  0xd503245f, /* hint    34 */
  0x580000b1, /* ldr     x17, .+20 */
  0x580000d2, /* ldr     x18, .+24 */
  0xd61f0220, /* br      x17 */
  0xd5033f9f, /* dsb     sy */
  0xd5033fdf /* isb */
};

#elif defined(__APPLE__)
/* Only difference to the linux variant is the chain register (x16).  */
static const uint32_t aarch64_trampoline_insns[] = {
  0xd503245f, /* hint    34 */
  0x580000b1, /* ldr     x17, .+20 */
  0x580000d0, /* ldr     x16, .+24 */
  0xd61f0220, /* br      x17 */
  0xd5033f9f, /* dsb     sy */
  0xd5033fdf /* isb */
};

#else
#error "Unsupported AArch64 platform for heap trampolines"
#endif

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

  struct aarch64_trampoline *trampoline
    = &tramp_ctrl_curr->trampolines[get_trampolines_per_page ()
				    - tramp_ctrl_curr->free_trampolines];

  /* Generate code for the trampoline, filling in those bits as required from
     the data passed into this function.  */

  /* Disable write protection for the MAP_JIT regions in this thread (see
     https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon) */
  pthread_jit_write_protect_np (0);

  memcpy (trampoline->insns, aarch64_trampoline_insns,
	  sizeof(aarch64_trampoline_insns));
  trampoline->func_ptr = func;
  trampoline->chain_ptr = chain;

  /* Re-enable write protection.  */
  pthread_jit_write_protect_np (1);

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
