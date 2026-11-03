// Opt-in outer RCS write-fence cache flush for the qualified ADL-S target.
#ifndef kern_adls_rcs_flush_hpp
#define kern_adls_rcs_flush_hpp
#include "kern_xelp_platform.hpp"
#include "kern_xelp_os.hpp"
namespace ADLSRCSFlush {
inline bool requested(const XELP::Profile &profile,XELP::OS os,bool host,
                      bool exactKernelABI,bool optIn) {
 return optIn && exactKernelABI && host && os==XELP::OS::Tahoe &&
  profile.identity==0x46808086 && profile.revision==0x0C &&
  !profile.overridden() && XELP::same(profile,XELP::identify(0x46808086,0x0C));
}
}
#endif
