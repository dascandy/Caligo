#include "catch.hpp"
#include "rsa.h"

TEST_CASE("RSA 32-bit encrypt/decrypt", "[RSA]") {
  bignum<32> p = 63863;
  bignum<32> q = 65413;
  bignum<32> n = p * q;
//  bignum<32> lcm_pq = 2088670572;
  bignum<32> e = 65537;
  bignum<32> d = 717714593;

  bignum<32> pt = 132098123;

  bignum<32> accum = 1;
  bignum<32> z = pt;
  for (size_t x = 0; x < 32; x++) {
    if (e.bit(x)) accum = (accum * z).naive_reduce(n);
    std::cout << "E " << to_string(accum) << "\n";
    z = (z * z).naive_reduce(n);
    std::cout << "E " << to_string(z) << "\n";
  }
  bignum<32> ct = accum;
  accum = 1;
  z = ct;
  for (size_t x = 0; x < 32; x++) {
    if (d.bit(x)) accum = (accum * z).naive_reduce(n);
    std::cout << "D " << to_string(accum) << "\n";
    z = (z * z).naive_reduce(n);
    std::cout << "D " << to_string(z) << "\n";
  }
  bignum<32> pt2 = accum;

  CHECK(pt2 == pt);

  rsa_private_key<32> key(n, e, d);
  auto ct2 = rsaep(key, pt);
  auto npt = rsadp(key, ct2);
  REQUIRE(pt == npt);
}
/*
TEST_CASE("RSA 1024 bit encrypt/decrypt", "[RSA]") {
  bignum<1024> n = { 
    0xd0b750c8, 0x554b64c7, 0xa9d34d06, 0x8e020fb5, 0x2fea1b39, 0xc47971a3, 0x59f0eec5, 0xda0437ea, 
    0x3fc94597, 0xd8dbff54, 0x44f6ce5a, 0x3293ac89, 0xb1eebb3f, 0x712b3ad6, 0xa06386e6, 0x401985e1, 
    0x9898715b, 0x1ea32ac0, 0x3456fe17, 0x96d31ed4, 0xaf389f4f, 0x675c23c4, 0x21a12549, 0x1e740fda, 
    0xc4322ec2, 0xd46ec945, 0xddc34922, 0x7b492191, 0xc9049145, 0xfb2f8c29, 0x98c486a8, 0x40eac4d3, 
  };
  bignum<1024> e = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x859e499b, 0x8a186c8e, 0xe6196954, 
    0x170eb806, 0x8593f0d7, 0x64150a6d, 0x2e5d3fea, 0x7d9d0d33, 0xac553eec, 0xd5c3f27a, 0x310115d2, 
    0x83e49377, 0x820195c8, 0xe67781b6, 0xf112a625, 0xb14b747f, 0xa4cc13d0, 0x6eba0917, 0x246c775f, 
    0x5c732865, 0x701ae934, 0x9ea8729c, 0xde0bbade, 0x38204e63, 0x359a46e6, 0x72a8d0a2, 0xfd530069,  
  };
  bignum<1024> d = {
    0x27b7119a, 0x09edb827, 0xc13418c8, 0x20b522a1, 0xee08de0e, 0x4bb28106, 0xdb6bb914, 0x98a3b361, 
    0xab293af8, 0x3fefcdd8, 0xa6bd2134, 0xca4afacf, 0x64a0e33c, 0x014f48f4, 0x7530f884, 0x7cc9185c, 
    0xbedec0d9, 0x238c8f1d, 0x5498f71c, 0x7c0cff48, 0xdc213421, 0x742e3435, 0x0ca94007, 0x753cc0e5, 
    0xa783264c, 0xf49ff644, 0xffea9425, 0x3cfe8685, 0x9acd2a22, 0x76ca4e72, 0x15f8ebaa, 0x2f188f51,  
  };
  bignum<1024> c = {
    0x6cf87c6a, 0x65925df6, 0x719eef5f, 0x1262edc6, 0xf8a0a0a0, 0xd21c535c, 0x64580745, 0xd9a268a9, 
    0x5b50ff3b, 0xe24ba8b6, 0x49ca47c3, 0xa760b71d, 0xdc3903f3, 0x6aa1d98e, 0x87c53b33, 0x70be784b, 
    0xffcb5bc1, 0x80dea2ac, 0xc15bb12e, 0x681c889b, 0x89b8f3de, 0x78050019, 0xdcdbb68c, 0x051b04b8, 
    0x80f0f8c4, 0xe855321f, 0xfed89767, 0xfc9d4a8a, 0x27a5d82b, 0xa450b247, 0x8c21e118, 0x43c2f539,  
  };
  bignum<1024> k = {
    0x5c7bce72, 0x3cf4da05, 0x3e503147, 0x242c6067, 0x8c67e8c2, 0x2467f033, 0x6b6d5c31, 0xf14088cb, 
    0x3d6cefb6, 0x48db132c, 0xb32e9509, 0x2f3d9bcd, 0x1cab51e6, 0x8bd3a892, 0xab359cdf, 0xf556785a, 
    0xe0670863, 0x3d39a061, 0x8f9d6d70, 0xf6bdeb6b, 0x777e7dd9, 0xacc41f19, 0x560c71a6, 0x8479c8a0, 
    0x7b14fb9a, 0x4c765fd2, 0x92ae56dd, 0x2f2143b6, 0x2649cc70, 0xfb604fdc, 0x5cc1ade6, 0xe29de235,  
  };

  rsa_private_key<1024> key(n, e, d);
  auto ct = rsaep(key, k);
  auto pt = rsadp(key, c);
  CHECK(ct == c);
  CHECK(pt == k);
}

TEST_CASE("RSA 2048 bit encrypt/decrypt", "[RSA]") {
  bignum<2048> n = {
    0xd9a098da, 0x000ac58e, 0xfb7d6c98, 0x9b746844, 0x4d369d98, 0x65eec869, 0x6a4bc54e, 0xf47f4d04, 
    0xbb5fb531, 0x134d9edc, 0x1254c966, 0x5f96462c, 0x190a1c47, 0xccf970b3, 0xa00a922a, 0x37e5ceb5, 
    0x48ad638c, 0x425ee963, 0x10db234a, 0x97ed0434, 0x2de813b5, 0xb6a4eb1a, 0xce5fef5b, 0x0c22e233, 
    0x0e4f285a, 0x76fb3d95, 0x5ef13df1, 0xe2288c7e, 0x8974220f, 0x773b4360, 0x29e5a8b0, 0x3f7c9d1c, 
    0x8743ad2e, 0x6edab660, 0x4fae2122, 0x44039c0b, 0xc2dffe1f, 0xb8a37fa8, 0xb935fb31, 0x4764c76f, 
    0x5aba87e9, 0xd5466ec4, 0x13ce3a72, 0xaf0eebd0, 0xb483f2c2, 0x98b35248, 0x538823d5, 0x27f40e22, 
    0x1557c8b2, 0x5257a131, 0xadc7f81a, 0xdf9b481c, 0x8c244053, 0x56ea4200, 0x9676bd66, 0x06e7fede, 
    0x6b76a6a2, 0x64a97507, 0xf15f0f12, 0xdec9d7bd, 0x473af9e0, 0xae86399c, 0xf1f2d402, 0x1f13325d,  
  };
  bignum<2048> e = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xd107cf43, 0xa692284d, 0xbe81e069, 
    0x739b0fa1, 0x21f605ee, 0xcc587c05, 0x84051469, 0x06b56e10, 0x42a19196, 0x663e14b4, 0xd6d13288, 
    0xb708cd99, 0x8db8aa5a, 0xd53966d5, 0x47509426, 0xa2e28946, 0xae2eae99, 0xc9fd7478, 0xde2dfed9, 
    0x0b185414, 0xb2a83d18, 0x4147cfdc, 0xc1843140, 0x53e655aa, 0x7c5af0e0, 0x65f2eb13, 0x9dfd0ddd, 
    0x64d878fb, 0x87fd3959, 0x6a804d48, 0x403e12a1, 0xaee476e8, 0xdb65a9bb, 0x15f50881, 0xeb235553, 
    0x1549c1f2, 0x6832ab88, 0x12aa1085, 0x8b24832e, 0x5f8498b4, 0x3249707d, 0x14b88fac, 0x7c238b2b, 
    0xaa010058, 0xc2454aa8, 0x91f5dba1, 0x1ff450af, 0xcd26afc5, 0x71858df2, 0x230ee7c3, 0x3e86e814, 
    0xc5278012, 0x8400e8ef, 0xd60a3980, 0x557b3e95, 0xe8e6b01c, 0xe80d9a3a, 0x08faf173, 0x0d065ef1,  
  };
  bignum<2048> d = {
    0x592cf1ce, 0xbd9cb996, 0x16c57c22, 0x81851c02, 0x258ff73b, 0xedceffec, 0x955ab877, 0xe21abbc4, 
    0xe8488e83, 0x6593ae9d, 0x1f21cde1, 0xbf089f1e, 0x03190752, 0xcd9cee2e, 0x66f478a5, 0x0a154c65, 
    0x4e530534, 0xbed03759, 0xe15b95f6, 0x5c7302fc, 0x95868f37, 0xa2b438e6, 0x40e25820, 0xa3f529c5, 
    0xe1f7caf4, 0x61a5cff3, 0xdb3d85b3, 0xee920ba7, 0xb39ce115, 0xce23a584, 0xe46dc576, 0xb81ba4ed, 
    0xf3b4fd3d, 0x711ab36c, 0xb4260875, 0x2d4ede82, 0x65f07267, 0x1bf9652f, 0xfc9706af, 0xd6f729d4, 
    0x49ea8f2a, 0x6be7f8c9, 0xd167f89e, 0xff4a8a5f, 0x6c2b57b2, 0x9f9981a3, 0x31204280, 0xa110c32f, 
    0x34f158e8, 0xbb020225, 0x8abd92f7, 0x75747df6, 0x484ad66c, 0x120d6ef6, 0x242801a1, 0xcff83d06, 
    0x5497701e, 0xb8b6647d, 0x69b4dc91, 0xc49ca434, 0x792a46b8, 0xc18ee703, 0x54add44d, 0x771db2b9,  
  };
  bignum<2048> c = {
    0x534d1f57, 0xd948cac5, 0x80b88b92, 0x2bc47bc3, 0xd64c8cd1, 0x262bbf09, 0x44b99833, 0xec94d072, 
    0xc1a1496b, 0xe44d47a9, 0xc419dc40, 0x3855a4b1, 0xcb2bb30e, 0x56e0cc5f, 0xd557d343, 0x73d785db, 
    0xe70d67e3, 0x0355fc22, 0x8a353b05, 0x432a4087, 0x4ba84253, 0xaf5cc52d, 0x3ab4118e, 0x8ca1e28e, 
    0x6c9c6107, 0x60e753f8, 0x7a159127, 0x74ccb80b, 0x00ca21e8, 0x5926143c, 0x1ed8385a, 0x607c4e55, 
    0xfa531f1f, 0x208bb3f2, 0x3bc0c4ef, 0xf4c27206, 0x8f993915, 0x7bc61f54, 0x27cc32f0, 0x17ef31f6, 
    0x363c8a73, 0x6ec984da, 0x763ebea5, 0xeb94d83f, 0xa31d7022, 0x3ec5503c, 0xfd97e598, 0xd883f43a, 
    0xca5e884b, 0x702a2f76, 0xd2986591, 0x81cb5180, 0xe25faf56, 0xc9aa0ebe, 0x49413b9a, 0xcbbefde9, 
    0x5ec102ee, 0x4e351a8f, 0xf8d5a3fb, 0xdcee448f, 0xf466dffb, 0x45fdc0a0, 0xb3d31b3d, 0x192bb5cb,  
  };
  bignum<2048> k = {
    0x4d252235, 0x7254b309, 0xb5239d33, 0x50d5c0c4, 0xd3b2f196, 0x7e17da27, 0x450b12a4, 0x70c5283f, 
    0x10b7a2c3, 0x3ea10081, 0x66481245, 0xbcb2480c, 0xcd4ac015, 0x5a82435e, 0xa44a2cdc, 0x92e545b3, 
    0x4ecd1ae8, 0x7c5d6fb1, 0xaaba9ea1, 0x5053edf2, 0x3f82c391, 0x8d9ec313, 0x3a52ba80, 0x76df5c91, 
    0x8d166c90, 0xa605d175, 0x5b205d7e, 0x994103f8, 0xb1b9afc1, 0x6e6b274e, 0x2a0043e0, 0xad54186c, 
    0x95a72569, 0x10f6e7ad, 0xfa885fd4, 0xc67b1edc, 0x63e83e85, 0xf8992e42, 0x39319b18, 0xbe859203, 
    0x0b79f4ac, 0x9e16a465, 0x0d9d7675, 0xa4f45640, 0x18ab85c0, 0xdb5790e4, 0x78df656f, 0x886dc461, 
    0xbc33c9ff, 0x32a0fd75, 0xa73a1c66, 0x26934c28, 0xc923a1c1, 0xefe80d59, 0xfb2efeb6, 0xaae82c0f, 
    0xc8cbfbf3, 0x06eda799, 0xe0c2a3ef, 0xb3c60915, 0x6b2715f2, 0x8c00ff58, 0x075e34ed, 0x5d327ce0,  
  };

  rsa_private_key<2048> key(n, e, d);
  auto ct = rsaep(key, k);
  auto pt = rsadp(key, c);
  CHECK(ct == c);
  CHECK(pt == k);
}
*/

