#include <Arduino.h>

#include "aes-256/tiny-aes.h"
#include "configuration.h"

#include "TestUtil.h"
#include <string.h>
#include <unity.h>

#ifdef ARCH_NRF52

// ---------------------------------------------------------------------------
// DWT cycle-counter helpers (Cortex-M3/M4 CMSIS)
// ---------------------------------------------------------------------------

static void enable_cycle_counter(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

static inline void reset_cycle_counter(void)
{
    DWT->CYCCNT = 0;
}

static inline uint32_t read_cycle_counter(void)
{
    return DWT->CYCCNT;
}

// ---------------------------------------------------------------------------
// Benchmark parameters
// ---------------------------------------------------------------------------

static constexpr int ITERATIONS = 100;
static constexpr int BUF_SIZE = 4096;                          // 256 AES blocks
static constexpr int BLOCKS_PER_BUF = BUF_SIZE / AES_BLOCKLEN; // 256

// ---------------------------------------------------------------------------
// Test: AES-256 KeyExpansion cycles
// ---------------------------------------------------------------------------

void test_aes256_keyexpansion_cycles(void)
{
    uint8_t key[32];
    uint8_t iv[AES_BLOCKLEN];
    struct AES_ctx ctx;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x00, sizeof(iv));

    // Warmup
    AES_init_ctx_iv(&ctx, key, iv);

    enable_cycle_counter();

    uint32_t total = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        reset_cycle_counter();
        AES_init_ctx_iv(&ctx, key, iv);
        total += read_cycle_counter();
    }

    uint32_t avg = total / ITERATIONS;

    char msg[80];
    snprintf(msg, sizeof(msg), "AES-256 KeyExpansion: %lu cycles (avg over %d runs)", (unsigned long)avg, ITERATIONS);
    TEST_MESSAGE(msg);

    // Sanity: should be in a plausible range (100 – 10,000 cycles)
    TEST_ASSERT_GREATER_THAN_UINT32(100, avg);
    TEST_ASSERT_LESS_THAN_UINT32(10000, avg);
}

// ---------------------------------------------------------------------------
// Test: AES-256-CTR cycles per block
// ---------------------------------------------------------------------------

void test_aes256_ctr_cycles(void)
{
    uint8_t key[32];
    uint8_t iv[AES_BLOCKLEN];
    static uint8_t buf[BUF_SIZE]; // static to avoid stack pressure
    struct AES_ctx ctx;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x00, sizeof(iv));

    // Warmup: run once to warm I-cache / D-cache
    AES_init_ctx_iv(&ctx, key, iv);
    memset(buf, 0xAA, sizeof(buf));
    AES_CTR_xcrypt_buffer(&ctx, buf, sizeof(buf));

    enable_cycle_counter();

    uint32_t total = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        AES_init_ctx_iv(&ctx, key, iv);
        memset(buf, 0xAA, sizeof(buf));

        reset_cycle_counter();
        AES_CTR_xcrypt_buffer(&ctx, buf, sizeof(buf));
        total += read_cycle_counter();
    }

    uint32_t avg_per_buf = total / ITERATIONS;
    uint32_t avg_per_block = avg_per_buf / BLOCKS_PER_BUF;

    char msg[120];
    snprintf(msg, sizeof(msg), "AES-256-CTR: %lu cycles/block, %lu cycles/4KB buf (avg over %d runs, %d blocks/buf)",
             (unsigned long)avg_per_block, (unsigned long)avg_per_buf, ITERATIONS, BLOCKS_PER_BUF);
    TEST_MESSAGE(msg);

    // Sanity: expect 400 – 5,000 cycles/block for a software AES-256-CTR on Cortex-M4
    TEST_ASSERT_GREATER_THAN_UINT32(400, avg_per_block);
    TEST_ASSERT_LESS_THAN_UINT32(5000, avg_per_block);
}

#else // !ARCH_NRF52

void test_aes256_keyexpansion_cycles(void)
{
    TEST_IGNORE_MESSAGE("DWT cycle counter only available on nRF52 (Cortex-M4)");
}

void test_aes256_ctr_cycles(void)
{
    TEST_IGNORE_MESSAGE("DWT cycle counter only available on nRF52 (Cortex-M4)");
}

#endif // ARCH_NRF52

// ---------------------------------------------------------------------------
// Unity boilerplate
// ---------------------------------------------------------------------------

void setUp(void) {}

void tearDown(void) {}

void setup()
{
    delay(10);
    delay(2000);

    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_aes256_keyexpansion_cycles);
    RUN_TEST(test_aes256_ctr_cycles);
    exit(UNITY_END());
}

void loop() {}
