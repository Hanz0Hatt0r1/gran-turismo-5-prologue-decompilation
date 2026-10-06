#include <assert.h>
#include <stdint.h>

#include "gt5_vector_normalize.h"

static void test_compacts_odd_words(void) {
    uint32_t words[] = {0, 1, 2, 3, 4, 5, 6, 7};
    gt5_compact_stride2_u32(words, 4);
    assert(words[0] == 1);
    assert(words[1] == 3);
    assert(words[2] == 5);
    assert(words[3] == 7);
}

static void test_zero_count_is_noop(void) {
    uint32_t words[] = {10, 11, 12};
    gt5_compact_stride2_u32(words, 0);
    assert(words[0] == 10);
    assert(words[1] == 11);
    assert(words[2] == 12);
}

static void test_one_element_is_safe_in_place(void) {
    uint32_t words[] = {100, 200, 300};
    gt5_compact_stride2_u32(words, 1);
    assert(words[0] == 200);
}

int main(void) {
    test_compacts_odd_words();
    test_zero_count_is_noop();
    test_one_element_is_safe_in_place();
    return 0;
}
