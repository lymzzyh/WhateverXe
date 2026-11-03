// Local servicing-build adaptation for one already-validated TGLVA page.
#pragma once
#include "kern_uhd770_page.hpp"
namespace LocalVideoABI {
static constexpr size_t PageSize=4096;
static const uint8_t ReferenceSHA256[]{0xc7,0x77,0x94,0x2f,0xc,0x9,0xbc,0xfa,0x6d,0xb8,0xb9,0x14,0xa7,0x10,0x68,0x8f,0x50,0xc0,0x43,0xd2,0x22,0x89,0x5a,0xc4,0xa0,0x42,0x7a,0xe4,0xf6,0x7b,0x9d,0x1f};
static constexpr uint64_t FileOffset=0x10000;
static constexpr size_t PatchOffset=0xd73;
static const uint8_t Replacement[]{'2','5','G','3','3','2',0};
static const uint8_t Original[]{'2','5','G','2','4','1',0};
inline bool matches(const void *data,size_t size,uint64_t offset,bool validated,bool tainted) {
 if(!data || size!=PageSize || offset!=FileOffset || !validated || tainted)return false;
 const auto page=static_cast<const uint8_t *>(data);
 return !memcmp(page+PatchOffset,Original,sizeof(Replacement)) &&
        UHD770Page::matches(page,PageSize,ReferenceSHA256);
}
inline void apply(void *data) {
 memcpy(static_cast<uint8_t *>(data)+PatchOffset,Replacement,sizeof(Replacement));
}
}
