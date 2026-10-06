#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gt5_keyed_config.h"

struct test_state {
    uint32_t offsets[8];
    uintptr_t destinations[8];
    const uint8_t *base;
    size_t applied;
    size_t cleaned;
    uint32_t cleaned_offsets[8];
};

static int apply_item(
    const gt5_keyed_item *item,
    void *destination,
    void *context)
{
    struct test_state *state = (struct test_state *)context;
    assert(destination != NULL);
    assert(state->applied < 8u);
    state->offsets[state->applied] = item->destination_offset;
    state->destinations[state->applied] = (uintptr_t)destination;
    ++state->applied;
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
    assert(state->cleaned < 8u);
    state->cleaned_offsets[state->cleaned] = item->destination_offset;
    ++state->cleaned;
}

static int fail_fifth_item(
    const gt5_keyed_item *item,
    void *destination,
    void *context)
{
    struct test_state *state = (struct test_state *)context;
    (void)item;
    assert(destination != NULL);
    ++state->applied;
    return state->applied == 5u ? -7 : 0;
}

static void test_success_preserves_observed_order(void)
{
    uint8_t storage[0x80] = {0};
    struct test_state state = {{0}, {0}, storage, 0u, 0u, {0}};

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
    assert(state.destinations[0] == (uintptr_t)(storage + 0x00u));
    assert(state.offsets[1] == 0x14u);
    assert(state.offsets[2] == 0x28u);
    assert(state.offsets[3] == 0x3cu);
    assert(state.offsets[4] == 0x50u);
    assert(state.destinations[4] == (uintptr_t)(storage + 0x50u));
    assert(state.cleaned == 0u);
}

static void test_failure_cleans_in_reverse(void)
{
    uint8_t storage[0x80] = {0};
    struct test_state state = {{0}, {0}, storage, 0u, 0u, {0}};

    assert(gt5_apply_keyed_startup_config(
        storage,
        NULL,
        NULL,
        NULL,
        NULL,
        fail_fifth_item,
        cleanup_item,
        &state) == -7);
    assert(state.applied == 5u);
    assert(state.cleaned == 4u);
    assert(state.cleaned_offsets[0] == 0x3cu);
    assert(state.cleaned_offsets[1] == 0x28u);
    assert(state.cleaned_offsets[2] == 0x14u);
    assert(state.cleaned_offsets[3] == 0x00u);
}

int main(void)
{
    test_success_preserves_observed_order();
    test_failure_cleans_in_reverse();
    return 0;
}
