#if defined(__TARGET_ARCH_x86)
#include "vmlinux-x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux-arm64.h"
#elif defined(__TARGET_ARCH_riscv)
#include "vmlinux-riscv.h"
#else
/*
 * For other architectures, we don't have a vmlinux.h file. But the normal dae
 * bpf program doesn't need it. So we just include the x86 vmlinux.h file to
 * make the build pass.
 */
#include "vmlinux-x86.h"
#endif
