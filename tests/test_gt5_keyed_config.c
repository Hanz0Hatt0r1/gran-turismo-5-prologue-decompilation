#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gt5_keyed_config.h"

struct test_state {
    uint32_t offsets[8];
    size_t applied;
    size_t cleaned;
};

static int apply_item(
    const gt5_keyed_item *item,
    void *destination,
    void *context)
{
    struct test_state *state = (struct test_state *)context;
    assert(destination != NULL);
    assert(state->applied < 8u);
    state->offsets[state->applied++] = item->destination_offset;
    assert(item->key_name != NULL);
    if (strcmp(item->key_name, "GT5_FINGERPRINT_SIZE") == 0) {
        assert(item->payload_size == sizeof(uint32_t));
        assert(*(const uint32_t *)item->payload == 16u);
    }
    return 0;
}

static void cleanup_item(
    const gt5_keyed_item *item,
    void *context)
{
    struct test_state *state = (struct test_state *)context;
    (void)item;
    ++state->cleaned;
}

static int fail_second_item(
    const gt5_keyed_item *item,
    void *destination,
    void *context)
{
    struct test_state *state = (struct test_state *)context;
    (void)item;
    assert(destination != NULL);
    ++state->applied;
    return state->applied == 2u ? -7 : 0;
}

static void test_success_preserves_observed_order(void)
{
    uint8_t storage[0x80] = {0};
    struct test_state state = {{0}, 0u, 0u};

    assert(gt5_apply_keyed_startup_config(
        storage,
        NULL,
        NULL,
        NULL,
        NULL,
        apply_item,
        cleanup_item,
        &state) == 0);

    assert(state.applied == 5u);
    assert(state.offsets[0] == 0x00u);
    assert(state.offsets[1] == 0x14u);
    assert(state.offsets[2] == 0x28u);
    assert(state.offsets[3] == 0x3cu);
    assert(state.offsets[4] == 0x50u);
    assert(state.cleaned == 0u);
}

static void test_failure_cleans_in_reverse(void)
{
    uint8_t storage[0x80] = {0};
    struct test_state state = {{0}, 0u, 0u};

    assert(gt5_apply_keyed_startup_config(
        storage,
        NULL,
        NULL,
        NULL,
        NULL,
        fail_second_item,
        cleanup_item,
        &state) == -7);
    assert(state.applied == 2u);
    assert(state.cleaned == 1u);
}

int main(void)
{
    test_success_preserves_observed_order();
    test_failure_cleans_in_reverse();
    return 0;
}
