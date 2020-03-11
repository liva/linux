#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/io.h>
#include <asm/host_ops.h>

#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>

// dirty hack
#include <uapi/linux/mman.h>
#include <uapi/linux/fs.h>
int open(const char *pathname, int flags);
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t read(int fd, void *buf, size_t count);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);
off_t lseek(int fd, off_t offset, int whence);
int close(int fd);
#define MAP_FAILED (void *)-1

static int uiofd;
static int configfd;

struct uio_pci_sysdata {
	int domain; /* PCI domain */
};

static void *uio_pci_map_bus(struct pci_bus *bus, unsigned int devfn, int where)
{
  panic("");
  return NULL;
}


static int uio_pci_generic_read(struct pci_bus *bus, unsigned int devfn,
			  int where, int size, u32 *val)
{
  if ((bus->number == 0) && (PCI_SLOT(devfn) == 0) && (PCI_FUNC(devfn) == 0)) {
    pread(configfd, val, size, where);
    return PCIBIOS_SUCCESSFUL;
  } else {
    return PCIBIOS_FUNC_NOT_SUPPORTED;
  }
}

static int uio_pci_generic_write(struct pci_bus *bus, unsigned int devfn,
			    int where, int size, u32 val)
{
  if ((bus->number == 0) && (PCI_SLOT(devfn) == 0) && (PCI_FUNC(devfn) == 0)) {
    pwrite(configfd, &val, size, where);
    return PCIBIOS_SUCCESSFUL;
  } else {
    return PCIBIOS_FUNC_NOT_SUPPORTED;
  }
}

void __iomem *__pci_ioport_map(struct pci_dev *dev,
			       unsigned long port, unsigned int nr)
{
  panic("");
  //	return rumpcomp_pci_map(port, nr);
  return NULL;
}

#ifdef __HAVE_PCIIDE_MACHDEP_COMPAT_INTR_ESTABLISH
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pciidereg.h>
#include <dev/pci/pciidevar.h>

void *
pciide_machdep_compat_intr_establish(device_t dev,
        const struct pci_attach_args *pa, int chan,
        int (*func)(void *), void *arg)
{
  panic("");
        /* pci_intr_handle_t ih; */
        /* struct pci_attach_args mypa = *pa; */

        /* mypa.pa_intrline = PCIIDE_COMPAT_IRQ(chan); */
        /* if (pci_intr_map(&mypa, &ih) != 0) */
        /*         return NULL; */
        /* return rumpcomp_pci_irq_establish(ih, func, arg); */
}

__strong_alias(pciide_machdep_compat_intr_disestablish, pci_intr_disestablish);
#endif /* __HAVE_PCIIDE_MACHDEP_COMPAT_INTR_ESTABLISH */

/* from drivers/pci/xen-pcifront.c */
static int pci_lib_claim_resource(struct pci_dev *dev, void *data)
{
	int i;
	struct resource *r;

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		r = &dev->resource[i];

		if (!r->parent && r->start && r->flags) {
			dev_info(&dev->dev, "claiming resource %s/%d\n",
				pci_name(dev), i);
			if (pci_claim_resource(dev, i)) {
				dev_err(&dev->dev,
					"Could not claim resource %s/%d!",
					pci_name(dev), i);
			}
		}
	}

	return 0;
}

struct pci_ops uio_pci_root_ops = {
	.map_bus = uio_pci_map_bus,
	.read = uio_pci_generic_read,
	.write = uio_pci_generic_write,
};

int pagemapfd;

static dma_addr_t vtop(u64 vaddr) {
  u64 paddr = 0;
  u64 offset = (vaddr / 0x1000 /*sysconf(_SC_PAGESIZE)*/) * sizeof(u64);
  u64 e;
  
  // https://www.kernel.org/doc/Documentation/vm/pagemap.txt
  pread(pagemapfd, &e, sizeof(u64), offset);
  if (e & (1ULL << 63)) {            // page present ?
    paddr = e & ((1ULL << 55) - 1);  // pfn mask
    paddr = paddr * 0x1000/*sysconf(_SC_PAGESIZE)*/;
    // add offset within page
    paddr = paddr | (vaddr & (0x1000 /*sysconf(_SC_PAGESIZE)*/ - 1));
  }
  return paddr;
}

static void *posix_physmem_alloc(struct device *dev, size_t size,
                            dma_addr_t *dma_handle, gfp_t gfp,
                            unsigned long attrs)
{
  void *ret;

  ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED | MAP_ANONYMOUS, -1, 0);
  if (ret != MAP_FAILED) {
    *dma_handle = vtop((u64)ret);
  }
  return ret;
}

static void posix_physmem_free(struct device *dev, size_t size,
                          void *cpu_addr, dma_addr_t dma_addr,
                          unsigned long attrs)
{
  panic("");
}

static dma_addr_t posix_physmem_map_page(struct device *dev, struct page *page,
                                      unsigned long offset, size_t size,
                                      enum dma_data_direction dir,
                                      unsigned long attrs)
{
  return vtop((u64)page_to_virt(page)) + offset;
}

static int posix_physmem_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
                             enum dma_data_direction dir,
                             unsigned long attrs)
{
  int i;
  struct scatterlist *sg;

  for_each_sg(sgl, sg, nents, i) {
    void *va;
    
    BUG_ON(!sg_page(sg));
    va = sg_virt(sg);
    sg_dma_address(sg) = (dma_addr_t)vtop((u64)va);
    sg_dma_len(sg) = sg->length;
  }
  return nents;
}

static int posix_physmem_dma_supported(struct device *dev, u64 mask)
{
        return 1;
}

struct dma_map_ops posix_dma_ops =
  {
   .alloc             = posix_physmem_alloc,
   .free              = posix_physmem_free,
   .map_sg            = posix_physmem_map_sg,
   .map_page          = posix_physmem_map_page,
   .dma_supported     = posix_physmem_dma_supported,
  };

static void uio_int_thread(void *_data)
{
  unsigned icount;
  int err;
  unsigned char command_high;
  struct irq_data *data = (struct irq_data *)_data;

  /* Read and cache command value */
  err = pread(configfd, &command_high, 1, 5);
  if (err != 1) {
    panic("failed to uio config read");
  }
  command_high &= ~0x4;
      
  while(1) {    
    /* Wait for next interrupt. */
    err = read(uiofd, &icount, 4);
    if (err != 4) {
      panic("failed to uio read");
    }
    
    lkl_trigger_irq(data->irq);

    /* Re-enable interrupts. */
    err = pwrite(configfd, &command_high, 1, 5);
    if (err != 1) {
      panic("failed to uio config write");
    }
  }
}

int irq_num = -1;

int uio_irq_request(struct irq_data *data)
{
        int ret, int_irq;
        struct irq_desc *desc = irq_to_desc(data->irq);
        const char *name = desc->name ? desc->name : "null"; /* XXX */
	if (irq_num != -1) {
	  if (data->irq == irq_num) {
	    // just ignore
	    return 0;
	  }
	  return -ENOSPC;
	}
	irq_num = data->irq;

        /* setup IRQ */
        int_irq = lkl_get_free_irq(name);

	if (!lkl_ops->thread_create(uio_int_thread, data)) {
	  return -ENOMEM;
	}

        return 0;
}

void uio_irq_release(struct irq_data *data)
{
        /* XXX: NOP */
}

static int __init aurora_uio_init(void)
{
  struct pci_bus *bus;
  struct uio_pci_sysdata *sd;
  int busnum = 0;

  uiofd = open("/dev/uio0", O_RDONLY);
  if (uiofd < 0) {
    return -1;
  }
  configfd = open("/sys/class/uio/uio0/device/config", O_RDWR);
  if (configfd < 0) {
    return -1;
  }

  pagemapfd = open("/proc/self/pagemap", O_RDONLY);
  if (pagemapfd < 0) {
    return -1;
  }

  sd = kzalloc(sizeof(*sd), GFP_KERNEL);
  if (!sd)
    return -1;
  
  pr_info("PCI: root bus %02x: using default resources\n", busnum);
  bus = pci_scan_bus(busnum, &uio_pci_root_ops, sd);
  if (!bus) {
    kfree(sd);
    return -1;
  }
  pci_walk_bus(bus, pci_lib_claim_resource, NULL);
  pci_bus_add_devices(bus);
  
  return 0;
}

subsys_initcall(aurora_uio_init);
