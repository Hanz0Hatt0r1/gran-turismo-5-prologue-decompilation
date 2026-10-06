#include <assert.h>
#include <stdint.h>

#include "gt5_dispatch_walker.h"

struct memory_word {
    uint32_t address;
    uint32_t value;
};

struct test_context {
    const struct memory_word *words;
    size_t count;
    uint32_t codes[8];
    uint32_t tocs[8];
    size_t calls;
};

static uint32_t read_u32(uint32_t address, void *opaque)
{
    struct test_context *ctx = (struct test_context *)opaque;
    for (size_t i = 0; i < ctx->count; ++i) {
        if (ctx->words[i].address == address) {
            return ctx->words[i].value;
        }
    }
    assert(!"unexpected address");
    return 0;
}

static void invoke(uint32_t code_va, uint32_t toc_va, void *opaque)
{
    struct test_context *ctx = (struct test_context *)opaque;
    assert(ctx->calls < 8);
    ctx->codes[ctx->calls] = code_va;
    ctx->tocs[ctx->calls] = toc_va;
    ++ctx->calls;
}

static void test_two_node_traversal(void)
{
    static const struct memory_word words[] = {
        {0x1000, 0x1100},
        {0x1004, 0x1200},
        {0x1100, 0x2000},
        {0x1200, 0x1208},
        {0x120c, 0x3000},
        {0x1210, 0x4000},
        {0x2000, 0x2100},
        {0x2104, 0x2200},
        {0x2208, 0x5000},
        {0x220c, 0x6000},
    };
    struct test_context ctx = {words, sizeof(words) / sizeof(words[0]), {0}, {0}, 0};

    gt5_walk_ppu_dispatch_list(0x1000, read_u32, invoke, &ctx);

    assert(ctx.calls == 2);
    assert(ctx.codes[0] == 0x3000);
    assert(ctx.tocs[0] == 0x4000);
    assert(ctx.codes[1] == 0x5000);
    assert(ctx.tocs[1] == 0x6000);
}

static void test_null_head_is_noop(void)
{
    struct test_context ctx = {0};
    gt5_walk_ppu_dispatch_list(0, read_u32, invoke, &ctx);
    assert(ctx.calls == 0);
}

int main(void)
{
    test_two_node_traversal();
    test_null_head_is_noop();
    return 0;
}
