# YooK, Y3lib Branch

An ultra-lightweight (~550 LoC) inline hooking and runtime instrumentation framework for Windows user-mode built in modern C++23.

> [!NOTE]
> **Architecture Support in this Branch:** Unlike standalone YooK (which supports x86, x64, and ARM64), **this Y3lib branch exclusively targets x64 (64-bit)**. This architectural restriction is intentional: the entire Y3lib ecosystem (including indirect syscall stubs, SSN extraction, stack spoofing, and allocator routines) is built and optimized strictly for 64-bit Windows execution.

This edition of **YooK** is uniquely specialized and integrated into the **Y3lib** ecosystem, replacing standard runtime dependencies, heap allocators, and Win32 user-mode APIs with hardened indirect syscalls and high-speed custom heap management.

---

> **Architectural Philosophy:** Why rely on bloated disassemblers or noisy user-mode Win32 hooks when you can weaponize hardware Trap Flags and silent indirect syscalls to manipulate memory under the radar?

---

## What Makes the Y3lib Edition Superior?

While the standalone edition of YooK demonstrates the power of hardware-assisted instruction tracing without Length Disassembler Engines (LDEs), the **Y3lib Integrated Edition** evolves YooK into a stealthy, allocation-aware instrumentation engine:

| Feature / Metric | Standard YooK Standalone | YooK (Y3lib Integrated Edition) |
| :--- | :--- | :--- |
| **Virtual Memory Allocations** | Standard `VirtualAlloc` / `VirtualProtect` | **`Y3lib::Memory::Allocator` & Indirect Syscalls** (`Syscall_AllocateVirtualMemory`) |
| **Memory Protection Changes** | High-level `VirtualProtect` Win32 API hooks | **Syscall-backed protection transitions** via indirect SSN tables |
| **Heap Memory Overhead** | Standard C++ runtime CRT Heap (`malloc`/`operator new`) | **Zero-overhead fast tracked heap** (`Y3lib::Memory::Allocator::Instance().AllocateFast`) |
| **Instruction Cache Flushes** | Win32 `FlushInstructionCache` API | **Direct `Syscall_FlushInstructionCache`** bypassing user-mode API shims and AV/EDR hooks |
| **Memory Querying** | Standard `VirtualQuery` | **`Syscall_QueryVirtualMemory`** using internal Syscall resolver tables |
| **Container Footprint** | Standard CRT `std::vector` (CRT heap dependent) | **Modular `Y3lib::Memory::vector`** backed by isolated `STLAllocator` |
| **Hook Footprint** | ~510 Lines of Code | **~550 Lines of Code with complete kernel syscall independence** |

---

## Core Architecture & Hardware-Driven Mechanics

YooK eliminates traditional Length Disassembler Engines (like Zydis, Capstone, or HDE) and instead uses **hardware-assisted CPU execution traps**:

1. **Hardware Single-Step Decoding (x64):** 
   - Registers a localized Vectored Exception Handler (VEH) and arms a `PAGE_GUARD` on the target function prologue.
   - When the function is entered, the CPU faults into the VEH, captures the context, and sets the Trap Flag (`EFLAGS.TF`).
   - The CPU single-steps one instruction at a time, calculating exact machine instruction boundaries dynamically without needing any static lookup tables.
   - Once 5 stolen bytes are gathered, YooK builds the relocated trampoline, applies atomic 8-byte hot-patching (`InterlockedCompareExchange64`), and disarms the Trap Flag.

2. **Transient Memory & VEH Footprint:**
   - The microsecond hook calculation finishes and all active hooks reach `HookStatus::Hooked`, YooK unregisters its VEH handler from `ntdll!RtlRemoveVectoredExceptionHandler`.
   - Leaves zero passive handler registrations in the Windows kernel during steady-state execution.

4. **Dynamic Trampoline Branch Upgrading:**
   - Automatically detects and expands 2-byte Short Conditional Jumps (`0x70-0x7F`) into 6-byte Near Conditional Jumps (`0x0F 0x80-0x8F`).
   - Upgrades 2-byte Short Unconditional Jumps (`0xEB`) into 5-byte Near Jumps (`0xE9`).
   - Recalculates and repairs x64 ModR/M RIP-relative data displacements (`0xC7 == 0x05`) to keep reference pointers valid inside the relocated trampoline.

---

## Y3lib Subsystem Integration Details

### 1. Indirect Syscall Evasion
Rather than calling high-level `kernel32`/`kernelbase` exports (e.g. `VirtualProtect`, `VirtualAlloc`, `FlushInstructionCache`) which are universally monitored and hooked by endpoint security products, the Y3lib edition routes critical memory operations through indirect syscall shims (`Syscalls.h`):
- Memory discovery via `Syscall_QueryVirtualMemory`
- CPU pipeline synchronization via `Syscall_FlushInstructionCache`
- Memory protection adjustment via `Allocator::Protect`

### 2. High-Performance Arena & Fast Allocations
Hook internal structures (`Hook::Impl`), trampoline buffers, and runtime hook registries utilize `Y3lib::Memory::Allocator`:
- Trampolines allocated via `Allocator::AllocateVirtual` with near-memory proximity searching (`AllocNearby`).
- Internal vector registries (`Y3lib::Memory::vector`) allocate from fast heap pools rather than the default CRT heap, ensuring hook state data does not pollute normal CRT heaps.

---

## Usage Example

```cpp
#include <iostream>
#include "Y3lib/include/Y3lib/Yook/YooK/YooK.hpp"

// Target function to instrument
__declspec(noinline) void OriginalFunction(int value)
{
    std::cout << "[Target] Original called with: " << value << "\n";
}

// Custom detour function
void DetourFunction(int value)
{
    std::cout << "[Detour] Intercepted value: " << value << "\n";
}

int main()
{
    // Initialize the YooK hook instance
    YooK::Hook hook(reinterpret_cast<void*>(OriginalFunction), reinterpret_cast<void*>(DetourFunction));

    // Arm the hardware single-stepping and syscall-backed protection
    auto result = hook.enable();
    if (!result.has_value())
    {
        std::cerr << "Hooking failed\n";
        return -1;
    }

    // First call: Triggers PAGE_GUARD, steps CPU through prologue, hot-patches atomically
    OriginalFunction(1337);

    // Subsequent calls: Direct inline jump to detour with zero overhead
    OriginalFunction(42);

    // Disable and restore original prologue bytes
    hook.disable();
    return 0;
}
```