#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lkl_host.h>
#include <stdint.h>
#include <vepci.h>

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

#define SIZE_64M (1UL << 26)
#define PCIATB_PAGESIZE (1UL << 26)
#define MAX_SIZE (PCIATB_PAGESIZE * 512)

static uint64_t vehva = 0;
static uint64_t vevhm_size = 0;
static uint64_t vevhm_map_offset = 0;

void *lkl_ioremap(long addr, int size)
{
  if (addr == 0xfbe00000) {
    // map device register memory space to ve host address space
    /* get PCI ATB entry address from another VE node */
    vevhm_map_offset = addr % SIZE_64M;
    
    /* map PCI ATB entry to VEHVA */
    vevhm_size = ((size + vevhm_map_offset + SIZE_64M - 1) / SIZE_64M) * SIZE_64M;
    vehva = ve_register_pci_to_vehva(addr - vevhm_map_offset, vevhm_size);
    if (vehva == (uint64_t)-1)
      {
	lkl_printf("Fail to ve_register_pci_to_vehva()");
	return NULL;
      }
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

/**
 * @brief This function loads 8 bit data from address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 *
 * @return "8bit size data"
 */
inline uint8_t ve_pci_load8(uint64_t vehva) __attribute__((always_inline));
inline uint8_t ve_pci_load8(uint64_t vehva)
{
	uint8_t ret;
	asm volatile(
		"       lhm.b   %0, 0(%1)\n"
		"	fencem 2\n"
		: "=r"(ret)
		: "r"(vehva));
	return ret;
}

/**
 * @brief This function stores 8 bit data to address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 * @param[in] value 8 bit size data
 */
inline void ve_pci_store8(uint64_t vehva, uint8_t value) __attribute__((always_inline));
inline void ve_pci_store8(uint64_t vehva, uint8_t value)
{
	asm volatile(
		"	fencem 1\n"
		"       shm.b   %0, 0(%1)\n" ::"r"(value),
		"r"(vehva));
}

/**
 * @brief This function loads 16 bit data from address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 *
 * @return "16bit size data"
 */
inline uint16_t ve_pci_load16(uint64_t vehva) __attribute__((always_inline));
inline uint16_t ve_pci_load16(uint64_t vehva)
{
	uint16_t ret;
	asm volatile(
		"       lhm.h   %0, 0(%1)\n"
		"	fencem 2\n"
		: "=r"(ret)
		: "r"(vehva));
	return ret;
}

/**
 * @brief This function stores 16 bit data to address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 * @param[in] value 16 bit size data
 */
inline void ve_pci_store16(uint64_t vehva, uint16_t value) __attribute__((always_inline));
inline void ve_pci_store16(uint64_t vehva, uint16_t value)
{
	asm volatile(
		"	fencem 1\n"
		"       shm.h   %0, 0(%1)\n" ::"r"(value),
		"r"(vehva));
}

/**
 * @brief This function loads 32 bit data from address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 *
 * @return "32bit size data"
 */
inline uint32_t ve_pci_load32(uint64_t vehva) __attribute__((always_inline));
inline uint32_t ve_pci_load32(uint64_t vehva)
{
	uint32_t ret;
	asm volatile(
		"       lhm.w   %0, 0(%1)\n"
		"	fencem 2\n"
		: "=r"(ret)
		: "r"(vehva));
	return ret;
}

/**
 * @brief This function stores 32 bit data to address mapped to VEHVA
 *
 * @param[in] vehva Address of data
 * @param[in] value 32 bit size data
 */
inline void ve_pci_store32(uint64_t vehva, uint32_t value) __attribute__((always_inline));
inline void ve_pci_store32(uint64_t vehva, uint32_t value)
{
	asm volatile(
		"	fencem 1\n"
		"       shm.w   %0, 0(%1)\n" ::"r"(value),
		"r"(vehva));
}

int lkl_iomem_access(const volatile void *addr, void *res, int size, int write)
{
  if (((void *)0xfbe00000 <= addr) && (addr + size < (void *)0xfbe02000) && (vehva != 0)) {
    // dirty hack
    uint64_t mmaped_addr = vehva + vevhm_map_offset + (addr - (void *)0xfbe00000);
    // dirty hack
    switch (size) {
    case 8:
      if (write) {
	ve_pci_store64(mmaped_addr, *(uint64_t *)res);
      } else {
	*(uint64_t *)res = ve_pci_load64(mmaped_addr);
      }
      break;
    case 4:
      if (write) {
	ve_pci_store32(mmaped_addr, *(uint32_t *)res);
      } else {
	*(uint32_t *)res = ve_pci_load32(mmaped_addr);
      }
      break;
    case 2:
      if (write) {
	ve_pci_store16(mmaped_addr, *(uint16_t *)res);
      } else {
	*(uint16_t *)res = ve_pci_load16(mmaped_addr);
      }
      break;
    case 1:
      if (write) {
	ve_pci_store8(mmaped_addr, *(uint8_t *)res);
      } else {
	*(uint8_t *)res = ve_pci_load8(mmaped_addr);
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
