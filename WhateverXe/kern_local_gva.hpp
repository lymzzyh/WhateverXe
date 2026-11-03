// Select the admitted Intel renderer through AppleGVA's default branch.
#pragma once
#include "kern_uhd770_page.hpp"
namespace LocalGVA {
static constexpr size_t PageSize=4096;
static const uint8_t ReferenceSHA256[]{0xc8,0x54,0xc4,0x65,0x49,0xa2,0x32,0x66,0x96,0x12,0x9c,0x58,0xaa,0x42,0x75,0x8a,0x5f,0x23,0xb,0x4e,0x7b,0x34,0x51,0x90,0xc3,0x4a,0x38,0xc1,0x5f,0x97,0x90,0xc5};
static constexpr uint64_t FileOffset=0xc64c000;
static constexpr size_t PatchOffset=2216;
inline bool matches(const void *data,size_t size,uint64_t offset,bool validated,bool tainted) {
 if(!data || size!=PageSize || offset!=FileOffset || !validated || tainted)return false;
 auto page=static_cast<const uint8_t *>(data);
 return page[PatchOffset]=='M' && UHD770Page::matches(page,PageSize,ReferenceSHA256);
}
inline void apply(void *data) {
 // Make only GVA's MacPro7,1 exception inapplicable. The real board identity
 // and the exact native renderer checks remain unchanged.
 static_cast<uint8_t *>(data)[PatchOffset]='W';
}
}
