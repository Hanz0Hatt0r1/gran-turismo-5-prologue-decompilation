#include "gt5_vector_normalize.h"

void gt5_compact_stride2_u32(uint32_t *base, size_t count) {
    if (base == NULL || count == 0) {
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        base[i] = base[(i * 2u) + 1u];
    }
}
