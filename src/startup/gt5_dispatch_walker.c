#include "gt5_dispatch_walker.h"

void gt5_walk_ppu_dispatch_list(
    uint32_t head_va,
    gt5_read_u32_fn read_u32,
    gt5_invoke_ppu_fn invoke_ppu,
    void *context)
{
    uint32_t node_va;

    if (read_u32 == 0 || invoke_ppu == 0) {
        return;
    }

    node_va = read_u32(head_va, context);
    while (node_va != 0) {
        const uint32_t intermediate_va = read_u32(node_va + 0x04u, context);
        const uint32_t record_va = read_u32(intermediate_va + 0x08u, context);
        const uint32_t code_va = read_u32(record_va + 0x00u, context);
        const uint32_t toc_va = read_u32(record_va + 0x04u, context);

        invoke_ppu(code_va, toc_va, context);
        node_va = read_u32(node_va + 0x00u, context);
    }
}
