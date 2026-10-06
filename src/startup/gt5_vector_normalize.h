#ifndef GT5_VECTOR_NORMALIZE_H
#define GT5_VECTOR_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Clean-room reconstruction of the repeated startup memory transform observed
 * in GT5 BCUS-98114 function 0x00010338.
 *
 * The transform reads base[1], base[3], ... and packs those 32-bit words into
 * base[0], base[1], ... for count elements. Bytes outside the first count
 * output elements are intentionally left unspecified.
 */
void gt5_compact_stride2_u32(uint32_t *base, size_t count);

#endif
