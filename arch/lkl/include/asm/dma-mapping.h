#ifndef _ASM_LKL_DMA_MAPPING_H
#define _ASM_LKL_DMA_MAPPING_H

extern struct dma_map_ops posix_dma_ops;

static inline struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return &posix_dma_ops;
}

#endif
