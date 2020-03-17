// SPDX-License-Identifier: GPL-2.0
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/swap.h>

unsigned long memory_start, memory_end;
static unsigned long _memory_start, mem_size;

void *empty_zero_page;

#include <uapi/linux/mman.h>
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);
#define MAP_64MB       0x800000
#define PCIATB_PAGESIZE (1UL << 26)
uint64_t ve_register_mem_to_pci(void *mem, size_t size);

uint64_t pci_vhsaa_all;
void *vemva_all = NULL;
static void *malloc_dma(size_t size) {
  if (size > PCIATB_PAGESIZE) {
    lkl_printf("Fail to allocate memory");
    lkl_ops->panic();
  }
  if (vemva_all != NULL) {
    lkl_printf("Fail to allocate memory");
    lkl_ops->panic();
  }
  vemva_all = mmap(NULL, PCIATB_PAGESIZE, PROT_READ | PROT_WRITE,
	       MAP_ANONYMOUS | MAP_SHARED | MAP_64MB, -1, 0);
  if (NULL == vemva_all)
        {
	  lkl_printf("Fail to allocate memory");
	  lkl_ops->panic();
	}
  
  pci_vhsaa_all = ve_register_mem_to_pci(vemva_all, PCIATB_PAGESIZE);
  if (pci_vhsaa_all == (uint64_t)-1)
    {
      lkl_printf("Fail to ve_register_mem_to_pci()");
      lkl_ops->panic();
    }
  return vemva_all;
}


void __init bootmem_init(unsigned long mem_sz)
{
	mem_size = mem_sz;

	_memory_start = (unsigned long)malloc_dma(mem_size);
	memory_start = _memory_start;
	BUG_ON(!memory_start);
	memory_end = memory_start + mem_size;

	if (PAGE_ALIGN(memory_start) != memory_start) {
		mem_size -= PAGE_ALIGN(memory_start) - memory_start;
		memory_start = PAGE_ALIGN(memory_start);
		mem_size = (mem_size / PAGE_SIZE) * PAGE_SIZE;
	}
	pr_info("memblock address range: 0x%lx - 0x%lx\n", memory_start,
		memory_start+mem_size);
	/*
	 * Give all the memory to the bootmap allocator, tell it to put the
	 * boot mem_map at the start of memory.
	 */
	max_low_pfn = virt_to_pfn(memory_end);
	min_low_pfn = virt_to_pfn(memory_start);
	memblock_add(memory_start, mem_size);

	empty_zero_page = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	memset((void *)empty_zero_page, 0, PAGE_SIZE);

	{
		unsigned long zones_size[MAX_NR_ZONES] = {0, };

		zones_size[ZONE_NORMAL] = (mem_size) >> PAGE_SHIFT;
		free_area_init(zones_size);
	}
}

void __init mem_init(void)
{
	max_mapnr = (((unsigned long)high_memory) - PAGE_OFFSET) >> PAGE_SHIFT;
	/* this will put all memory onto the freelists */
	totalram_pages_add(memblock_free_all());
	pr_info("Memory available: %luk/%luk RAM\n",
		(nr_free_pages() << PAGE_SHIFT) >> 10, mem_size >> 10);
}

/*
 * In our case __init memory is not part of the page allocator so there is
 * nothing to free.
 */
void free_initmem(void)
{
}

void free_mem(void)
{
  //	lkl_ops->mem_free((void *)_memory_start);
}
