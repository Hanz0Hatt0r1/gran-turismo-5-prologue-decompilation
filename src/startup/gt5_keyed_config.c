#include "gt5_keyed_config.h"

/* Provenance: clean-room model of GT5 BCUS-98114 function 0x000106ac. */

static const uint32_t kFingerprintOffset = 0x00u;
static const uint32_t kFingerprintSizeOffset = 0x14u;
static const uint32_t kCertificateOffset = 0x28u;
static const uint32_t kPrivateKeyOffset = 0x3cu;
static const uint32_t kTvBaseKeyOffset = 0x50u;

/* Observed GT5 startup code uses an immediate value of 16 for fingerprint size. */
static const uint32_t kFingerprintSize = 16u;

int gt5_apply_keyed_startup_config(
    uint8_t *destination_base,
    const void *fingerprint,
    const void *certificate,
    const void *private_key,
    const void *tv_base_key,
    gt5_keyed_apply_fn apply,
    gt5_keyed_cleanup_fn cleanup,
    void *context)
{
    static const gt5_keyed_item template_items[] = {
        {kFingerprintOffset, "GT5_FINGERPRINT", NULL, 0u},
        {kFingerprintSizeOffset, "GT5_FINGERPRINT_SIZE", NULL, sizeof(uint32_t)},
        {kCertificateOffset, "GT5_CLIENT_CERTIFICATE", NULL, 0u},
        {kPrivateKeyOffset, "GT5_CLIENT_PRIVATEKEY", NULL, 0u},
        {kTvBaseKeyOffset, "GT5P_TVBASEKEY", NULL, 0u},
    };
    gt5_keyed_item items[sizeof(template_items) / sizeof(template_items[0])];
    size_t applied = 0u;

    if (destination_base == NULL || apply == NULL) {
        return -1;
    }

    items[0] = template_items[0];
    items[0].payload = fingerprint;
    items[1] = template_items[1];
    items[1].payload = &kFingerprintSize;
    items[2] = template_items[2];
    items[2].payload = certificate;
    items[3] = template_items[3];
    items[3].payload = private_key;
    items[4] = template_items[4];
    items[4].payload = tv_base_key;

    for (size_t i = 0u; i < sizeof(items) / sizeof(items[0]); ++i) {
        const gt5_keyed_item *item = &items[i];
        const int rc = apply(item, destination_base + item->destination_offset, context);
        if (rc != 0) {
            if (cleanup != NULL) {
                while (applied > 0u) {
                    --applied;
                    cleanup(&items[applied], context);
                }
            }
            return rc;
        }
        ++applied;
    }

    return 0;
}
