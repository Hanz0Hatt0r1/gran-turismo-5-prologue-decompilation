#ifndef GT5_KEYED_CONFIG_H
#define GT5_KEYED_CONFIG_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t destination_offset;
    const char *key_name;
    const void *payload;
    uint32_t payload_size;
} gt5_keyed_item;

typedef int (*gt5_keyed_apply_fn)(
    const gt5_keyed_item *item,
    void *destination,
    void *context);

typedef void (*gt5_keyed_cleanup_fn)(
    const gt5_keyed_item *item,
    void *context);

/*
 * Clean-room reconstruction of the observable shape of GT5 BCUS-98114
 * startup helper 0x000106ac.
 *
 * The recovered routine initializes five adjacent destinations and, on its
 * fallback path, cleans them in reverse order. Payload contents are intentionally
 * opaque; only the observed offsets and the fingerprint-size value are modeled.
 */
int gt5_apply_keyed_startup_config(
    uint8_t *destination_base,
    const void *fingerprint,
    const void *certificate,
    const void *private_key,
    const void *tv_base_key,
    gt5_keyed_apply_fn apply,
    gt5_keyed_cleanup_fn cleanup,
    void *context);

#endif
