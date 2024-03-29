#include <benchmark/benchmark.h>
#include "caligo/rsa.h"
#include "caligo/aes.h"
#include "caligo/gcm.h"
#include <x86intrin.h>

static void RSA_RSAEP_2048(benchmark::State& state) {
  Caligo::bignum<2048> n = {
    0xd9a098da, 0x000ac58e, 0xfb7d6c98, 0x9b746844, 0x4d369d98, 0x65eec869, 0x6a4bc54e, 0xf47f4d04,
    0xbb5fb531, 0x134d9edc, 0x1254c966, 0x5f96462c, 0x190a1c47, 0xccf970b3, 0xa00a922a, 0x37e5ceb5,
    0x48ad638c, 0x425ee963, 0x10db234a, 0x97ed0434, 0x2de813b5, 0xb6a4eb1a, 0xce5fef5b, 0x0c22e233,
    0x0e4f285a, 0x76fb3d95, 0x5ef13df1, 0xe2288c7e, 0x8974220f, 0x773b4360, 0x29e5a8b0, 0x3f7c9d1c,
    0x8743ad2e, 0x6edab660, 0x4fae2122, 0x44039c0b, 0xc2dffe1f, 0xb8a37fa8, 0xb935fb31, 0x4764c76f,
    0x5aba87e9, 0xd5466ec4, 0x13ce3a72, 0xaf0eebd0, 0xb483f2c2, 0x98b35248, 0x538823d5, 0x27f40e22,
    0x1557c8b2, 0x5257a131, 0xadc7f81a, 0xdf9b481c, 0x8c244053, 0x56ea4200, 0x9676bd66, 0x06e7fede,
    0x6b76a6a2, 0x64a97507, 0xf15f0f12, 0xdec9d7bd, 0x473af9e0, 0xae86399c, 0xf1f2d402, 0x1f13325d,
  };
  Caligo::bignum<2048> e = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xd107cf43, 0xa692284d, 0xbe81e069,
    0x739b0fa1, 0x21f605ee, 0xcc587c05, 0x84051469, 0x06b56e10, 0x42a19196, 0x663e14b4, 0xd6d13288,
    0xb708cd99, 0x8db8aa5a, 0xd53966d5, 0x47509426, 0xa2e28946, 0xae2eae99, 0xc9fd7478, 0xde2dfed9,
    0x0b185414, 0xb2a83d18, 0x4147cfdc, 0xc1843140, 0x53e655aa, 0x7c5af0e0, 0x65f2eb13, 0x9dfd0ddd,
    0x64d878fb, 0x87fd3959, 0x6a804d48, 0x403e12a1, 0xaee476e8, 0xdb65a9bb, 0x15f50881, 0xeb235553,
    0x1549c1f2, 0x6832ab88, 0x12aa1085, 0x8b24832e, 0x5f8498b4, 0x3249707d, 0x14b88fac, 0x7c238b2b,
    0xaa010058, 0xc2454aa8, 0x91f5dba1, 0x1ff450af, 0xcd26afc5, 0x71858df2, 0x230ee7c3, 0x3e86e814,
    0xc5278012, 0x8400e8ef, 0xd60a3980, 0x557b3e95, 0xe8e6b01c, 0xe80d9a3a, 0x08faf173, 0x0d065ef1,
  };
  Caligo::bignum<2048> k = {
    0x4d252235, 0x7254b309, 0xb5239d33, 0x50d5c0c4, 0xd3b2f196, 0x7e17da27, 0x450b12a4, 0x70c5283f,
    0x10b7a2c3, 0x3ea10081, 0x66481245, 0xbcb2480c, 0xcd4ac015, 0x5a82435e, 0xa44a2cdc, 0x92e545b3,
    0x4ecd1ae8, 0x7c5d6fb1, 0xaaba9ea1, 0x5053edf2, 0x3f82c391, 0x8d9ec313, 0x3a52ba80, 0x76df5c91,
    0x8d166c90, 0xa605d175, 0x5b205d7e, 0x994103f8, 0xb1b9afc1, 0x6e6b274e, 0x2a0043e0, 0xad54186c,
    0x95a72569, 0x10f6e7ad, 0xfa885fd4, 0xc67b1edc, 0x63e83e85, 0xf8992e42, 0x39319b18, 0xbe859203,
    0x0b79f4ac, 0x9e16a465, 0x0d9d7675, 0xa4f45640, 0x18ab85c0, 0xdb5790e4, 0x78df656f, 0x886dc461,
    0xbc33c9ff, 0x32a0fd75, 0xa73a1c66, 0x26934c28, 0xc923a1c1, 0xefe80d59, 0xfb2efeb6, 0xaae82c0f,
    0xc8cbfbf3, 0x06eda799, 0xe0c2a3ef, 0xb3c60915, 0x6b2715f2, 0x8c00ff58, 0x075e34ed, 0x5d327ce0,
  };

  Caligo::rsa_public_key<2048> key(n, e);

  // Perform setup here
  for (auto _ : state) {
    k = key.rsaep(k);
  }
}

static void RSA_RSADP_2048(benchmark::State& state) {
  Caligo::bignum<2048> n = {
    0xd9a098da, 0x000ac58e, 0xfb7d6c98, 0x9b746844, 0x4d369d98, 0x65eec869, 0x6a4bc54e, 0xf47f4d04,
    0xbb5fb531, 0x134d9edc, 0x1254c966, 0x5f96462c, 0x190a1c47, 0xccf970b3, 0xa00a922a, 0x37e5ceb5,
    0x48ad638c, 0x425ee963, 0x10db234a, 0x97ed0434, 0x2de813b5, 0xb6a4eb1a, 0xce5fef5b, 0x0c22e233,
    0x0e4f285a, 0x76fb3d95, 0x5ef13df1, 0xe2288c7e, 0x8974220f, 0x773b4360, 0x29e5a8b0, 0x3f7c9d1c,
    0x8743ad2e, 0x6edab660, 0x4fae2122, 0x44039c0b, 0xc2dffe1f, 0xb8a37fa8, 0xb935fb31, 0x4764c76f,
    0x5aba87e9, 0xd5466ec4, 0x13ce3a72, 0xaf0eebd0, 0xb483f2c2, 0x98b35248, 0x538823d5, 0x27f40e22,
    0x1557c8b2, 0x5257a131, 0xadc7f81a, 0xdf9b481c, 0x8c244053, 0x56ea4200, 0x9676bd66, 0x06e7fede,
    0x6b76a6a2, 0x64a97507, 0xf15f0f12, 0xdec9d7bd, 0x473af9e0, 0xae86399c, 0xf1f2d402, 0x1f13325d,
  };
  Caligo::bignum<2048> d = {
    0x592cf1ce, 0xbd9cb996, 0x16c57c22, 0x81851c02, 0x258ff73b, 0xedceffec, 0x955ab877, 0xe21abbc4,
    0xe8488e83, 0x6593ae9d, 0x1f21cde1, 0xbf089f1e, 0x03190752, 0xcd9cee2e, 0x66f478a5, 0x0a154c65,
    0x4e530534, 0xbed03759, 0xe15b95f6, 0x5c7302fc, 0x95868f37, 0xa2b438e6, 0x40e25820, 0xa3f529c5,
    0xe1f7caf4, 0x61a5cff3, 0xdb3d85b3, 0xee920ba7, 0xb39ce115, 0xce23a584, 0xe46dc576, 0xb81ba4ed,
    0xf3b4fd3d, 0x711ab36c, 0xb4260875, 0x2d4ede82, 0x65f07267, 0x1bf9652f, 0xfc9706af, 0xd6f729d4,
    0x49ea8f2a, 0x6be7f8c9, 0xd167f89e, 0xff4a8a5f, 0x6c2b57b2, 0x9f9981a3, 0x31204280, 0xa110c32f,
    0x34f158e8, 0xbb020225, 0x8abd92f7, 0x75747df6, 0x484ad66c, 0x120d6ef6, 0x242801a1, 0xcff83d06,
    0x5497701e, 0xb8b6647d, 0x69b4dc91, 0xc49ca434, 0x792a46b8, 0xc18ee703, 0x54add44d, 0x771db2b9,
  };
  Caligo::bignum<2048> k = {
    0x4d252235, 0x7254b309, 0xb5239d33, 0x50d5c0c4, 0xd3b2f196, 0x7e17da27, 0x450b12a4, 0x70c5283f,
    0x10b7a2c3, 0x3ea10081, 0x66481245, 0xbcb2480c, 0xcd4ac015, 0x5a82435e, 0xa44a2cdc, 0x92e545b3,
    0x4ecd1ae8, 0x7c5d6fb1, 0xaaba9ea1, 0x5053edf2, 0x3f82c391, 0x8d9ec313, 0x3a52ba80, 0x76df5c91,
    0x8d166c90, 0xa605d175, 0x5b205d7e, 0x994103f8, 0xb1b9afc1, 0x6e6b274e, 0x2a0043e0, 0xad54186c,
    0x95a72569, 0x10f6e7ad, 0xfa885fd4, 0xc67b1edc, 0x63e83e85, 0xf8992e42, 0x39319b18, 0xbe859203,
    0x0b79f4ac, 0x9e16a465, 0x0d9d7675, 0xa4f45640, 0x18ab85c0, 0xdb5790e4, 0x78df656f, 0x886dc461,
    0xbc33c9ff, 0x32a0fd75, 0xa73a1c66, 0x26934c28, 0xc923a1c1, 0xefe80d59, 0xfb2efeb6, 0xaae82c0f,
    0xc8cbfbf3, 0x06eda799, 0xe0c2a3ef, 0xb3c60915, 0x6b2715f2, 0x8c00ff58, 0x075e34ed, 0x5d327ce0,
  };

  Caligo::rsa_private_key<2048> key(n, d);

  // Perform setup here
  for (auto _ : state) {
    k = key.rsadp(k);
  }
}

static void RSA_RSAEP_2048_fastpath(benchmark::State& state) {
  Caligo::bignum<2048> n = {
    0xd9a098da, 0x000ac58e, 0xfb7d6c98, 0x9b746844, 0x4d369d98, 0x65eec869, 0x6a4bc54e, 0xf47f4d04,
    0xbb5fb531, 0x134d9edc, 0x1254c966, 0x5f96462c, 0x190a1c47, 0xccf970b3, 0xa00a922a, 0x37e5ceb5,
    0x48ad638c, 0x425ee963, 0x10db234a, 0x97ed0434, 0x2de813b5, 0xb6a4eb1a, 0xce5fef5b, 0x0c22e233,
    0x0e4f285a, 0x76fb3d95, 0x5ef13df1, 0xe2288c7e, 0x8974220f, 0x773b4360, 0x29e5a8b0, 0x3f7c9d1c,
    0x8743ad2e, 0x6edab660, 0x4fae2122, 0x44039c0b, 0xc2dffe1f, 0xb8a37fa8, 0xb935fb31, 0x4764c76f,
    0x5aba87e9, 0xd5466ec4, 0x13ce3a72, 0xaf0eebd0, 0xb483f2c2, 0x98b35248, 0x538823d5, 0x27f40e22,
    0x1557c8b2, 0x5257a131, 0xadc7f81a, 0xdf9b481c, 0x8c244053, 0x56ea4200, 0x9676bd66, 0x06e7fede,
    0x6b76a6a2, 0x64a97507, 0xf15f0f12, 0xdec9d7bd, 0x473af9e0, 0xae86399c, 0xf1f2d402, 0x1f13325d,
  };
  Caligo::bignum<2048> e = 65537;
  Caligo::bignum<2048> k = {
    0x4d252235, 0x7254b309, 0xb5239d33, 0x50d5c0c4, 0xd3b2f196, 0x7e17da27, 0x450b12a4, 0x70c5283f,
    0x10b7a2c3, 0x3ea10081, 0x66481245, 0xbcb2480c, 0xcd4ac015, 0x5a82435e, 0xa44a2cdc, 0x92e545b3,
    0x4ecd1ae8, 0x7c5d6fb1, 0xaaba9ea1, 0x5053edf2, 0x3f82c391, 0x8d9ec313, 0x3a52ba80, 0x76df5c91,
    0x8d166c90, 0xa605d175, 0x5b205d7e, 0x994103f8, 0xb1b9afc1, 0x6e6b274e, 0x2a0043e0, 0xad54186c,
    0x95a72569, 0x10f6e7ad, 0xfa885fd4, 0xc67b1edc, 0x63e83e85, 0xf8992e42, 0x39319b18, 0xbe859203,
    0x0b79f4ac, 0x9e16a465, 0x0d9d7675, 0xa4f45640, 0x18ab85c0, 0xdb5790e4, 0x78df656f, 0x886dc461,
    0xbc33c9ff, 0x32a0fd75, 0xa73a1c66, 0x26934c28, 0xc923a1c1, 0xefe80d59, 0xfb2efeb6, 0xaae82c0f,
    0xc8cbfbf3, 0x06eda799, 0xe0c2a3ef, 0xb3c60915, 0x6b2715f2, 0x8c00ff58, 0x075e34ed, 0x5d327ce0,
  };

  Caligo::rsa_public_key<2048> key(n, e);

  // Perform setup here
  for (auto _ : state) {
    k = key.rsaep(k);
  }
}

template <size_t N>
static Caligo::key_iv_pair<Caligo::AES<N>>& getKey() {
  if constexpr (N == 128) {
    static Caligo::key_iv_pair<Caligo::AES<N>> key{
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }
    };
    return key;
  } else {
    static Caligo::key_iv_pair<Caligo::AES<N>> key{
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }
    };
    return key;
  }
}

template <size_t N, size_t blocks>
static void AES_CTR_Bench(benchmark::State& state) {
  char ctr[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0x01 };
  char inbuffer[blocks * 16];
  char outbuffer[blocks * 16];

  for (auto _ : state) {
    Caligo::AesKeySchedule<N> s(getKey<N>().key);

    __m128i counter = _mm_loadu_si128((__m128i*)ctr);
    for (size_t n = 0; n < blocks; n++) {
      _mm_storeu_si128((__m128i*)outbuffer + n, _mm_loadu_si128((__m128i*)inbuffer + n) ^ Caligo::AesEncrypt(s, counter));
      ++counter[1];
    }
    benchmark::DoNotOptimize(outbuffer);
    benchmark::ClobberMemory();
  }
}

template <size_t N, size_t blocks>
static void AES_Bench(benchmark::State& state) {
  char inbuffer[blocks * 16];
  char outbuffer[blocks * 16];

  for (auto _ : state) {
    Caligo::AesKeySchedule<N> s(getKey<N>().key);

    for (size_t n = 0; n < blocks; n++) {
      _mm_storeu_si128((__m128i*)outbuffer + n, Caligo::AesEncrypt(s, _mm_loadu_si128((__m128i*)inbuffer + n)));
    }
    benchmark::DoNotOptimize(outbuffer);
    benchmark::ClobberMemory();
  }
}

template <size_t N, size_t blocks>
static void AES_GCM_Bench(benchmark::State& state) {
  Caligo::GCM<Caligo::AES<N>> gcm(getKey<N>());
  
  uint8_t inbuffer[blocks * 16];

  for (auto _ : state) {
    auto rv = gcm.Encrypt(inbuffer, {});
    benchmark::DoNotOptimize(rv);
    benchmark::ClobberMemory();
  }
}

static void AES_16KB_256(benchmark::State& state) { return AES_Bench<256, 1024>(state); }
static void AES_16KB_128(benchmark::State& state) { return AES_Bench<128, 1024>(state); }
static void AES_8KB_256(benchmark::State& state) { return AES_Bench<256, 512>(state); }
static void AES_8KB_128(benchmark::State& state) { return AES_Bench<128, 512>(state); }
static void AES_1KB_256(benchmark::State& state) { return AES_Bench<256, 64>(state); }
static void AES_1KB_128(benchmark::State& state) { return AES_Bench<128, 64>(state); }
static void AES_256_256(benchmark::State& state) { return AES_Bench<256, 16>(state); }
static void AES_256_128(benchmark::State& state) { return AES_Bench<128, 16>(state); }
static void AES_64_256(benchmark::State& state) { return AES_Bench<256, 4>(state); }
static void AES_64_128(benchmark::State& state) { return AES_Bench<128, 4>(state); }
static void AES_16_256(benchmark::State& state) { return AES_Bench<256, 1>(state); }
static void AES_16_128(benchmark::State& state) { return AES_Bench<128, 1>(state); }

static void AES_CTR_16KB_256(benchmark::State& state) { return AES_CTR_Bench<256, 1024>(state); }
static void AES_CTR_16KB_128(benchmark::State& state) { return AES_CTR_Bench<128, 1024>(state); }
static void AES_CTR_8KB_256(benchmark::State& state) { return AES_CTR_Bench<256, 512>(state); }
static void AES_CTR_8KB_128(benchmark::State& state) { return AES_CTR_Bench<128, 512>(state); }
static void AES_CTR_1KB_256(benchmark::State& state) { return AES_CTR_Bench<256, 64>(state); }
static void AES_CTR_1KB_128(benchmark::State& state) { return AES_CTR_Bench<128, 64>(state); }
static void AES_CTR_256_256(benchmark::State& state) { return AES_CTR_Bench<256, 16>(state); }
static void AES_CTR_256_128(benchmark::State& state) { return AES_CTR_Bench<128, 16>(state); }
static void AES_CTR_64_256(benchmark::State& state) { return AES_CTR_Bench<256, 4>(state); }
static void AES_CTR_64_128(benchmark::State& state) { return AES_CTR_Bench<128, 4>(state); }
static void AES_CTR_16_256(benchmark::State& state) { return AES_CTR_Bench<256, 1>(state); }
static void AES_CTR_16_128(benchmark::State& state) { return AES_CTR_Bench<128, 1>(state); }

static void AES_GCM_16KB_256(benchmark::State& state) { return AES_GCM_Bench<256, 1024>(state); }
static void AES_GCM_16KB_128(benchmark::State& state) { return AES_GCM_Bench<128, 1024>(state); }
static void AES_GCM_8KB_256(benchmark::State& state) { return AES_GCM_Bench<256, 512>(state); }
static void AES_GCM_8KB_128(benchmark::State& state) { return AES_GCM_Bench<128, 512>(state); }
static void AES_GCM_1KB_256(benchmark::State& state) { return AES_GCM_Bench<256, 64>(state); }
static void AES_GCM_1KB_128(benchmark::State& state) { return AES_GCM_Bench<128, 64>(state); }
static void AES_GCM_256_256(benchmark::State& state) { return AES_GCM_Bench<256, 16>(state); }
static void AES_GCM_256_128(benchmark::State& state) { return AES_GCM_Bench<128, 16>(state); }
static void AES_GCM_64_256(benchmark::State& state) { return AES_GCM_Bench<256, 4>(state); }
static void AES_GCM_64_128(benchmark::State& state) { return AES_GCM_Bench<128, 4>(state); }
static void AES_GCM_16_256(benchmark::State& state) { return AES_GCM_Bench<256, 1>(state); }
static void AES_GCM_16_128(benchmark::State& state) { return AES_GCM_Bench<128, 1>(state); }

// Register the function as a benchmark
BENCHMARK(RSA_RSAEP_2048);
BENCHMARK(RSA_RSAEP_2048_fastpath);
BENCHMARK(RSA_RSADP_2048);

BENCHMARK(AES_16KB_256);
BENCHMARK(AES_16KB_128);
BENCHMARK(AES_8KB_256);
BENCHMARK(AES_8KB_128);
BENCHMARK(AES_1KB_256);
BENCHMARK(AES_1KB_128);
BENCHMARK(AES_256_256);
BENCHMARK(AES_256_128);
BENCHMARK(AES_64_256);
BENCHMARK(AES_64_128);
BENCHMARK(AES_16_256);
BENCHMARK(AES_16_128);

BENCHMARK(AES_CTR_16KB_256);
BENCHMARK(AES_CTR_16KB_128);
BENCHMARK(AES_CTR_8KB_256);
BENCHMARK(AES_CTR_8KB_128);
BENCHMARK(AES_CTR_1KB_256);
BENCHMARK(AES_CTR_1KB_128);
BENCHMARK(AES_CTR_256_256);
BENCHMARK(AES_CTR_256_128);
BENCHMARK(AES_CTR_64_256);
BENCHMARK(AES_CTR_64_128);
BENCHMARK(AES_CTR_16_256);
BENCHMARK(AES_CTR_16_128);

BENCHMARK(AES_GCM_16KB_256);
BENCHMARK(AES_GCM_16KB_128);
BENCHMARK(AES_GCM_8KB_256);
BENCHMARK(AES_GCM_8KB_128);
BENCHMARK(AES_GCM_1KB_256);
BENCHMARK(AES_GCM_1KB_128);
BENCHMARK(AES_GCM_256_256);
BENCHMARK(AES_GCM_256_128);
BENCHMARK(AES_GCM_64_256);
BENCHMARK(AES_GCM_64_128);
BENCHMARK(AES_GCM_16_256);
BENCHMARK(AES_GCM_16_128);

// Run the benchmark
BENCHMARK_MAIN();


