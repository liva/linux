#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lkl_host.h>
#include <stdint.h>

#include "iomem.h"

#define IOMEM_OFFSET_BITS		24
#define MAX_IOMEM_REGIONS		256

#define IOMEM_ADDR_TO_INDEX(addr) \
	(((uintptr_t)addr) >> IOMEM_OFFSET_BITS)
#define IOMEM_ADDR_TO_OFFSET(addr) \
	(((uintptr_t)addr) & ((1 << IOMEM_OFFSET_BITS) - 1))
#define IOMEM_INDEX_TO_ADDR(i) \
	(void *)(uintptr_t)(i << IOMEM_OFFSET_BITS)

static struct iomem_region {
	void *data;
	int size;
	const struct lkl_iomem_ops *ops;
} iomem_regions[MAX_IOMEM_REGIONS];

void* register_iomem(void *data, int size, const struct lkl_iomem_ops *ops)
{
	int i;

	if (size > (1 << IOMEM_OFFSET_BITS) - 1)
		return NULL;

	for (i = 1; i < MAX_IOMEM_REGIONS; i++)
		if (!iomem_regions[i].ops)
			break;

	if (i >= MAX_IOMEM_REGIONS)
		return NULL;

	iomem_regions[i].data = data;
	iomem_regions[i].size = size;
	iomem_regions[i].ops = ops;
	return IOMEM_INDEX_TO_ADDR(i);
}

void unregister_iomem(void *base)
{
	unsigned int index = IOMEM_ADDR_TO_INDEX(base);

	if (index >= MAX_IOMEM_REGIONS) {
		lkl_printf("%s: invalid iomem_addr %p\n", __func__, base);
		return;
	}

	iomem_regions[index].size = 0;
	iomem_regions[index].ops = NULL;
}

void *uio_resource_addr = NULL;

void *lkl_ioremap(long addr, int size)
{
  if (addr == 0xfbe00000) {
    // dirty hack
    int fd = open("/sys/class/uio/uio0/device/resource0", O_RDWR);
    uio_resource_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    return (void *)addr;
  }
	int index = IOMEM_ADDR_TO_INDEX(addr);
	struct iomem_region *iomem = &iomem_regions[index];

	if (index >= MAX_IOMEM_REGIONS)
		return NULL;
	
	if (iomem->ops && size <= iomem->size)
		return IOMEM_INDEX_TO_ADDR(index);

	return NULL;
}

int lkl_iomem_access(const volatile void *addr, void *res, int size, int write)
{
  if (((void *)0xfbe00000 <= addr) && (addr + size < (void *)0xfbe02000) && (uio_resource_addr != NULL)) {
    // dirty hack
    void *mmaped_addr = uio_resource_addr + (addr - (void *)0xfbe00000);
    switch (size) {
    case 8:
      if (write) {
	*(uint64_t *)mmaped_addr = *(uint64_t *)res;
      } else {
	*(uint64_t *)res = *(uint64_t *)mmaped_addr;
      }
      break;
    case 4:
      if (write) {
	*(uint32_t *)mmaped_addr = *(uint32_t *)res;
      } else {
	*(uint32_t *)res = *(uint32_t *)mmaped_addr;
      }
      break;
    case 2:
      if (write) {
	*(uint16_t *)mmaped_addr = *(uint16_t *)res;
      } else {
	*(uint16_t *)res = *(uint16_t *)mmaped_addr;
      }
      break;
    case 1:
      if (write) {
	*(uint8_t *)mmaped_addr = *(uint8_t *)res;
      } else {
	*(uint8_t *)res = *(uint8_t *)mmaped_addr;
      }
      break;
    default:
      lkl_printf("not implemented yet\n");
      lkl_host_ops.panic();
    }
    return 0;
  }
	int index = IOMEM_ADDR_TO_INDEX(addr);
	struct iomem_region *iomem = &iomem_regions[index];
	int offset = IOMEM_ADDR_TO_OFFSET(addr);
	int ret;

	if (index > MAX_IOMEM_REGIONS || !iomem_regions[index].ops ||
	    offset + size > iomem_regions[index].size)
		return -1;

	if (write)
		ret = iomem->ops->write(iomem->data, offset, res, size);
	else
		ret = iomem->ops->read(iomem->data, offset, res, size);

	return ret;
}
