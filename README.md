# ⚡ YooK — Hardware-Assisted Inline Hooking & Dynamic Binary Instrumentation (Y3lib Edition)

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B20%20%2F%20C%2B%2B23-00599C?style=for-the-badge&logo=c%2B%2B" alt="C++20/C++23" />
  <img src="https://img.shields.io/badge/Architecture-x64%20%7C%20x86%20%7C%20ARM64-0078D6?style=for-the-badge&logo=windows" alt="Architectures" />
  <img src="https://img.shields.io/badge/LDE%20Dependency-Zero%20(Hardware%20Traced)-success?style=for-the-badge" alt="LDE Dependency" />
  <img src="https://img.shields.io/badge/Memory%20Evasion-Indirect%20Syscalls-purple?style=for-the-badge" alt="Indirect Syscalls" />
  <img src="https://img.shields.io/badge/License-All%20Rights%20Reserved%20(Proprietary)-red?style=for-the-badge" alt="License" />
</p>

---

> **`YooK` (Y3lib Edition) is an ultra-lightweight, hardware-assisted inline hooking and dynamic binary instrumentation engine for Windows user-mode. By leveraging CPU execution traps (Trap Flag single-stepping and guard pages) on Intel/AMD and atomic branch redirection on ARM64, `YooK` completely eliminates the need for heavy Length Disassembler Engines (LDEs like Zydis, Capstone, or HDE). This specialized `Y3lib` edition replaces all high-level Win32 memory APIs with hardened indirect NT syscalls and isolates all memory allocations inside `Y3lib::Memory::Allocator`.**

---

## 📑 Table of Contents

| Section | Focus Area | Navigation |
| :--- | :--- | :--- |
| **Architecture Matrix** | Multi-architecture matrix covering x64, x86, and ARM64 | [**Architecture Matrix ➔**](#-architecture-support-matrix-x64-x86-arm64) |
| **Hardware State Machine** | CPU single-step execution flow & LDE-free mechanics | [**State Machine ➔**](#-how-yook-works-the-hardware-state-machine) |
| **Comparison Matrix** | Legacy hookers vs standalone YooK vs Y3lib edition | [**Comparison ➔**](#-yook-y3lib-edition-vs-standalone--legacy-hookers) |
| **Per-Architecture Deep-Dive** | Technical mechanics for x64, x86, and ARM64 | [**Deep Dive ➔**](#-deep-dive-per-architecture-implementation-mechanics) |
| **Y3lib Evasion Hardening** | Indirect syscall integration, W^X arenas, isolated pools | [**Evasion Docs ➔**](#-y3lib-subsystem-integration--evasion-hardening) |
| **Quickstart & Example** | Complete compilable C++20/23 usage example | [**Quickstart ➔**](#-quickstart--complete-c-usage-example) |
| **License & Legal Notice** | Proprietary source code terms and academic review notice | [**License ➔**](#-license--legal-notice) |

---

## 🏛️ Architecture Support Matrix (x64, x86, ARM64)

`YooK` provides comprehensive multi-architecture support across all Windows execution targets:

| Architecture | Bitness | Decoding Strategy | Trampoline Return Stub | Proximity Allocation |
| :--- | :---: | :--- | :--- | :--- |
| **x64 (AMD64)** | 64-bit | `PAGE_GUARD` + `EFLAGS.TF` Single-Step Traversal | 14-byte `FF 25 [RIP+0]` Indirect JMP | `AllocNearby` within ±2GB (`0x7FFF0000`) |
| **x86 (IA-32)** | 32-bit | `PAGE_GUARD` + `EFLAGS.TF` Single-Step Traversal | 5-byte `E9 [rel32]` Relative JMP | Direct 4GB Virtual Alloc + W^X Heap Fallback |
| **ARM64 (AArch64)** | 64-bit | Fixed 4-byte Instruction Calculation (Near/Far) | 16-byte `LDR X16, [PC,#8]` + `BR X16` | Direct Virtual Alloc + W^X Heap Fallback |

---

## 🔬 How YooK Works: The Hardware State Machine

Traditional inline hookers (like MinHook or Microsoft Detours) embed full software disassemblers (LDEs) to parse instruction byte lengths in static memory. If an instruction contains an undocumented opcode, uncommon prefix combination, or AVX-512 extension, the LDE fails or corrupts the prologue.

**`YooK` rejects software disassembly entirely.** Instead, it weaponizes the CPU's native hardware execution flags to let the processor calculate its own instruction boundaries:

```
[Target Function Prologue]
          │
          ▼
1. Arm PAGE_GUARD via NtProtectVirtualMemory (Indirect Syscall)
          │
          ▼
2. First Call to TargetFunction() -> CPU generates STATUS_GUARD_PAGE_VIOLATION
          │
          ▼
3. VEH Intercepts -> Allocates Trampoline Buffer -> Sets EFLAGS.TF (Trap Flag) -> Restores PAGE_EXECUTE_READ
          │
          ▼
4. CPU Single-Steps Instruction 1 -> Generates STATUS_SINGLE_STEP
          │  ├── Instruction Length = context->XIP - lastInstructionStart
          │  ├── Relocates instruction into Trampoline buffer
          │  ├── Repairs Relative Displacements (JMP/CALL/ModR/M)
          │  └── Accumulated Stolen Bytes < 5?
          │         ├── YES: Keep EFLAGS.TF set -> Continue Single-Stepping
          │         └── NO:  Proceed to Exit Strategy
          ▼
5. Finalize Trampoline -> Append Architecture-Specific Return Stub -> Protect Trampoline (PAGE_EXECUTE_READ)
          │
          ▼
6. Atomic 8-Byte Hot-Patch (InterlockedCompareExchange64) -> JMP rel32 written to Prologue
          │
          ▼
7. Unregister VEH (RtlRemoveVectoredExceptionHandler) -> Zero Steady-State OS Footprint
```

---

## ⚔️ YooK (Y3lib Edition) vs Standalone & Legacy Hookers

| Capability / Metric | Legacy Hookers (MinHook / Detours) | Standalone YooK | **YooK (Y3lib Integrated Edition)** |
| :--- | :--- | :--- | :--- |
| **Disassembler Footprint** | Heavy (Zydis / HDE / Capstone: 10k–50k LoC) | **0 LoC** (Hardware Traced) | **0 LoC** (Hardware Traced) |
| **Memory Allocation Surface** | Standard Win32 `VirtualAlloc` | Standard Win32 `VirtualAlloc` | **`Y3lib::Memory::Allocator` (Indirect Syscall + W^X Dual-View)** |
| **Memory Protection Hooks** | `VirtualProtect` (Trigger for AV/EDR hooks) | `VirtualProtect` | **Indirect `NtProtectVirtualMemory` Syscall** |
| **Instruction Cache Flush** | `FlushInstructionCache` Win32 API | `FlushInstructionCache` Win32 API | **Indirect `NtFlushInstructionCache` Syscall** |
| **Heap Memory Overhead** | CRT Heap (`malloc` / `operator new`) | CRT Heap (`std::vector`) | **Isolated Fast Heap Pool (`Y3lib::Memory::vector`)** |
| **VEH Kernel Footprint** | Static or None | Unregistered post-hook | **Silent Dynamic Unregister (`RtlRemoveVectoredExceptionHandler`)** |
| **Source Complexity** | Heavy multi-file framework | ~510 Lines of Code | **~650 Lines of Code with 100% Kernel Syscall Independence** |

---

## 💻 Deep-Dive: Per-Architecture Implementation Mechanics

### 1. 64-bit Architecture (x64 / AMD64)

On 64-bit Windows, instructions have variable lengths (1 to 15 bytes), support RIP-relative addressing, and require 64-bit absolute return stubs:

- **Near-Memory Search (`AllocNearby`)**: Scans `NtQueryVirtualMemory` pages within `[target - 2GB, target + 2GB]` so that the initial 5-byte hook (`E9 [rel32]`) can reach the trampoline.
- **ModR/M RIP Displacement Fixing**: Scans prefix bytes (`REX 0x40-0x4F`, `0x66`, `0x67`, `0xF0`, `0xF2`, `0xF3`). If the instruction uses RIP-relative addressing (`ModR/M & 0xC7 == 0x05`), the displacement is recomputed relative to the trampoline's new `RIP`.
- **Branch Expansion**:
  - 2-byte Short Conditional Jumps (`0x70–0x7F`) are upgraded to 6-byte Near Conditional Jumps (`0x0F 0x80–0x8F`).
  - 2-byte Short Unconditional Jumps (`0xEB`) are upgraded to 5-byte Near Jumps (`0xE9`).
- **Trampoline Return Stub**: Emits a 14-byte 64-bit indirect jump (`FF 25 00 00 00 00 [8-byte retAddr]`), returning execution safely back to the original function body.

---

### 2. 32-bit Architecture (x86 / IA-32)

On 32-bit Windows (including WOW64 execution):

- **Flat 4GB Address Space**: Every virtual address is within 32-bit relative displacement reach. `AllocNearby` allocates directly via `Allocator::AllocateFast` without distance constraints.
- **Absolute Branch Chasing**: Unconditional indirect jumps (`FF 25 [disp32]`) resolve the 32-bit direct pointer from memory rather than computing RIP-relative offsets.
- **Trampoline Return Stub**: Emits a compact 5-byte relative jump (`E9 [rel32]`).
- **Atomic Hot-Patching**: Uses `InterlockedCompareExchange64` (`CMPXCHG8B`) to atomically write the 5-byte detour and NOP padding in a single CPU bus cycle.

---

### 3. 64-bit ARM Architecture (ARM64 / AArch64)

ARM64 utilizes fixed 4-byte instruction encoding, allowing instantaneous hook installation without VEH single-stepping:

- **Near Branch (±128MB)**:
  - If the detour is within ±128MB (`delta >= -134217728 && delta <= 134217724`), YooK steals 4 bytes (1 instruction) and writes a single immediate branch:
    ```cpp
    auto offsetMask = (static_cast<uint32_t>(delta >> 2) & 0x3FFFFFF);
    patchArea[0] = 0x14000000 | offsetMask; // B <offset>
    ```
- **Far Branch (> 128MB)**:
  - Steals 16 bytes (4 instructions) and writes an atomic 64-bit register-indirect branch:
    ```armasm
    LDR X16, [PC, #8]    ; 0x58000050
    BR  X16              ; 0xD61F0200
    .quad <DetourAddress>
    ```
  - Emits a hardware `MemoryBarrier()` between writing the target pointer and the branch instruction.

---

## 🛡️ Y3lib Subsystem Integration & Evasion Hardening

The Y3lib edition of `YooK` is designed specifically to operate undetected in hostile runtime environments monitored by EDRs and anti-cheat engines:

1. **Zero User-Mode API Hooks Triggered**:
   - Never calls `VirtualProtect` or `VirtualAlloc` from `kernel32.dll`.
   - All memory allocations route through `Y3lib::Memory::Allocator`, which dispatches indirect syscalls with dynamic SSNs and legitimate return-gadget trampolines.

2. **Dual-View W^X Executable Allocations**:
   - If page-granular virtual allocation is constrained, YooK falls back to `Allocator::AllocateExecutableHeap`, utilizing dual-view shared section mappings (`PAGE_READWRITE` write view + `PAGE_EXECUTE_READ` execution view) — eliminating `PAGE_EXECUTE_READWRITE` telemetry signatures entirely.

3. **Isolated Memory Registries**:
   - The active hook registry is backed by `Y3lib::Memory::vector`, which draws from isolated memory pools rather than polluting the standard CRT heap.

4. **Zero Steady-State Kernel Hooks**:
   - The VEH handler is registered dynamically on-demand and immediately removed via `RtlRemoveVectoredExceptionHandler` once hooks are installed.

---

## 🚀 Quickstart & Complete C++ Usage Example

```cpp
#include <iostream>
#include "Y3lib/Hooking/Inline/YooK/YooK/YooK.hpp"

// 1. Target function to intercept
__declspec(noinline) int TargetFunction(int a, int b)
{
    std::cout << "[Target] Executing original function: " << a << " + " << b << "\n";
    return a + b;
}

// 2. Custom detour function
int DetourFunction(int a, int b)
{
    std::cout << "[Detour] Intercepted call! Modifying parameters...\n";
    return (a * 10) + (b * 10);
}

int main()
{
    // 3. Instantiate YooK hook
    YooK::Hook hook(reinterpret_cast<void*>(&TargetFunction), reinterpret_cast<void*>(&DetourFunction));

    // 4. Arm hardware single-stepping and indirect syscall protection
    auto result = hook.enable();
    if (!result.has_value())
    {
        std::cerr << "[-] Failed to enable YooK hook!\n";
        return -1;
    }

    // 5. First call: Generates PAGE_GUARD fault -> CPU single-steps prologue -> hot-patches atomically
    int res1 = TargetFunction(5, 5); // Output: [Detour] Intercepted call! Modifying parameters... (returns 100)

    // 6. Subsequent calls: Direct inline JMP with zero overhead
    int res2 = TargetFunction(2, 3); // Output: [Detour] Intercepted call! Modifying parameters... (returns 50)

    // 7. Call original function via relocated Trampoline buffer
    auto original = reinterpret_cast<int(*)(int, int)>(hook.getTrampoline());
    if (original)
    {
        int origRes = original(5, 5); // Output: [Target] Executing original function: 5 + 5 (returns 10)
    }

    // 8. Disable hook and restore pristine original bytes
    hook.disable();
    int res3 = TargetFunction(5, 5); // Output: [Target] Executing original function: 5 + 5 (returns 10)

    return 0;
}
```

---

## 📜 License & Legal Notice

```text
====================================================================================================
                             PROPRIETARY SOURCE CODE & SOFTWARE NOTICE
====================================================================================================

Copyright (C) 2026 Yw3xY-Re. All Rights Reserved.

CONFIDENTIAL & PROPRIETARY:
This software, source code, headers, assembly routines, scripts, documentation, and all associated
intellectual property (collectively, the "Software") are the sole and exclusive proprietary property
of Yw3xY-Re (the "Author").

TERMS AND CONDITIONS OF USE:

1. PROHIBITION OF REDISTRIBUTION:
   No part of this Software, in source code, intermediate, or compiled binary form, may be reproduced,
   distributed, transmitted, displayed, broadcast, sublicensed, published, sold, or shared in any medium,
   electronic or mechanical, without the prior express written authorization of the Author.

2. PROHIBITION OF COMMERCIAL EXPLOITATION:
   Commercial use, monetization, integration into commercial or enterprise products, or use in any
   for-profit venture or consulting context is strictly and explicitly prohibited.

3. PROHIBITION OF DERIVATIVE WORKS & CODE PLAGIARISM:
   You may not alter, transform, adapt, translate, extract routines from, or build derivative works upon
   this codebase. Incorporating any logic, MASM assembly routines, or algorithms into other public or
   private repositories without written attribution and consent constitutes a violation of copyright.

4. PORTFOLIO & ACADEMIC SHOWCASE EVALUATION:
   Viewing and inspection of this repository is authorized exclusively for institutional admissions,
   academic evaluation, peer review, and verified portfolio verification purposes. This authorization
   does not grant any license to execute, copy, or redistribute the codebase.

5. DISCLAIMER OF WARRANTY & LIMITATION OF LIABILITY:
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
   LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION
   WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
====================================================================================================
```