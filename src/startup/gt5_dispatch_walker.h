#ifndef GT5_DISPATCH_WALKER_H
#define GT5_DISPATCH_WALKER_H

#include <stdint.h>

typedef uint32_t (*gt5_read_u32_fn)(uint32_t address, void *context);
typedef void (*gt5_invoke_ppu_fn)(uint32_t code_va, uint32_t toc_va, void *context);

/*
 * Clean-room reconstruction of the linked dispatch traversal observed in
 * GT5 BCUS-98114 function 0x00010970.
 *
 * Only the following memory relationships are assumed from the disassembly:
 *   node + 0x00 -> next node
 *   node + 0x04 -> intermediate object
 *   intermediate + 0x08 -> PPU code/TOC record
 *   record + 0x00 -> code address
 *   record + 0x04 -> TOC address
 *
 * The original loop invokes each pair through an indirect PPU call and
 * continues until the node pointer becomes zero.
 */
void gt5_walk_ppu_dispatch_list(
    uint32_t head_va,
    gt5_read_u32_fn read_u32,
    gt5_invoke_ppu_fn invoke_ppu,
    void *context);

#endif
