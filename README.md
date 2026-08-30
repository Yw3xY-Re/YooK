# ⚡ YooK — Hardware-Assisted Inline Hooking & Dynamic Instrumentation Framework

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B20%20%2F%20C%2B%2B23-00599C?style=for-the-badge&logo=c%2B%2B" alt="C++20/C++23" />
  <img src="https://img.shields.io/badge/Architecture-x64%20%7C%20x86%20%7C%20ARM64-0078D6?style=for-the-badge&logo=windows" alt="Architectures" />
  <img src="https://img.shields.io/badge/LDE%20Dependency-Zero%20(Hardware%20Traced)-success?style=for-the-badge" alt="LDE Dependency" />
  <img src="https://img.shields.io/badge/Footprint-~510%20LoC-purple?style=for-the-badge" alt="Footprint" />
  <img src="https://img.shields.io/badge/License-All%20Rights%20Reserved%20(Proprietary)-red?style=for-the-badge" alt="License" />
</p>

---

> **`YooK` is an ultra-lightweight (~510 LoC), multi-architecture inline hooking and runtime instrumentation framework for Windows user-mode (`x64`, `x86`, and `ARM64`) built in modern C++23 with C++20 backward compatibility. By weaponizing CPU hardware execution flags (Trap Flag single-stepping and guard pages) on Intel/AMD and atomic branch redirection on ARM64, `YooK` completely eliminates the need for heavy Length Disassembler Engines (LDEs like Zydis, Capstone, or HDE).**

---

## 📑 Table of Contents

| Section | Focus Area | Navigation |
| :--- | :--- | :--- |
| **Architecture Matrix** | Multi-architecture matrix covering x64, x86, and ARM64 | [**Architecture Matrix ➔**](#-architecture-support-matrix-x64-x86-arm64) |
| **Hardware State Machine** | CPU single-step execution flow & LDE-free mechanics | [**State Machine ➔**](#-how-yook-works-the-hardware-state-machine) |
| **Comparison Matrix** | Legacy hookers vs standalone YooK | [**Comparison ➔**](#-the-philosophy-hardware-vs-software-ldes) |
| **Deep-Dive Features** | Branch expansion, RIP-relative ModR/M fixups, trampoline peeling | [**Features ➔**](#-deep-dive-feature-breakdown) |
| **Technical Constraints** | Debugger collisions, packed binaries, and user-mode boundaries | [**Constraints ➔**](#-bottlenecks--technical-constraints) |
| **Integration Showcase** | Complete compilable C++20/23 usage example | [**Quickstart ➔**](#-integration-showcase) |
| **License & Legal Notice** | Proprietary source code terms and academic review notice | [**License ➔**](#-license--legal-notice) |

---

## 🏛️ Architecture Support Matrix (x64, x86, ARM64)

`YooK` provides comprehensive multi-architecture support across all Windows execution targets:

| Architecture | Bitness | Decoding Strategy | Trampoline Return Stub | Proximity Allocation |
| :--- | :---: | :--- | :--- | :--- |
| **x64 (AMD64)** | 64-bit | `PAGE_GUARD` + `EFLAGS.TF` Single-Step Traversal | 14-byte `FF 25 [RIP+0]` Indirect JMP | `AllocNearby` within ±2GB (`0x7FFF0000`) |
| **x86 (IA-32)** | 32-bit | `PAGE_GUARD` + `EFLAGS.TF` Single-Step Traversal | 5-byte `E9 [rel32]` Relative JMP | Direct 4GB Virtual Alloc |
| **ARM64 (AArch64)** | 64-bit | Fixed 4-byte Instruction Calculation (Near/Far) | 16-byte `LDR X16, [PC,#8]` + `BR X16` | Direct Virtual Alloc |

---

## 🔬 How YooK Works: The Hardware State Machine

Traditional inline hookers (like MinHook or Microsoft Detours) embed full software disassemblers (LDEs) to parse instruction byte lengths in static memory. If an instruction contains an undocumented opcode, uncommon prefix combination, or AVX-512 extension, the LDE fails or corrupts the prologue.

**`YooK` rejects software disassembly entirely.** Instead, it weaponizes the CPU's native hardware execution flags to let the processor calculate its own instruction boundaries:

```
[Target Function Prologue]
          │
          ▼
1. Arm PAGE_GUARD via VirtualProtect
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
7. Unregister VEH (RemoveVectoredExceptionHandler) -> Zero Steady-State OS Footprint
```

---

## ⚔️ The Philosophy: Hardware vs. Software (LDEs)

| Capability / Metric | Legacy Hookers (MinHook / Detours / PolyHook) | **YooK** |
| :--- | :--- | :--- |
| **Disassembler Footprint** | Heavy (Zydis / HDE / Capstone: 10,000–50,000 LoC) | **0 LoC** (Physical Silicon Decoded) |
| **Opcode Compatibility** | Fails on undocumented, AVX-512, or custom extensions | **100% Hardware Native** (Immune to LDE table gaps) |
| **Memory Allocation** | Standard CRT / VirtualAlloc | **`AllocNearby` (Proximity Aware) / VirtualAlloc** |
| **Thread Synchronization** | `SuspendThread` (Freezes threads, drops frames) | **Lock-Free Bus Lock (`InterlockedCompareExchange64`)** |
| **VEH Overhead** | Persistent or none | **Transient (Immediately unregistered post-hook)** |
| **Source Complexity** | Massive multi-file library | **~510 Lines of Code** (Ultra-compact single file) |

---

## 🔍 Deep-Dive Feature Breakdown

### 1. Zero Static Signature Footprint
Traditional hooking engines embed heavy decoding tables (like HDE or Zydis) containing massive data blocks to parse opcode prefixes, ModR/M fields, and SIB bytes. Because YooK delegates instruction decoding entirely to the physical CPU via the hardware single-step exception line, it contains zero hardcoded instruction lookup tables, drastically reducing binary bloat and signature footprints.

### 2. Lock-Free Atomic Thread Safety
Unlike legacy engines that use `SuspendThread` to freeze the entire process (causing render pipeline crashes and micro-stutters), YooK applies its final hook via a single-cycle 8-byte hardware bus lock (`InterlockedCompareExchange64`). Global registry writes are insulated by zero-overhead Windows Slim Reader/Writer (SRW) locks. The result is flawless multi-threaded stability without ever pausing background execution.

### 3. Dynamic Conditional Branch Upgrading
When relocating a function prologue to an allocated trampoline, 2-byte short jumps frequently break because the destination is now out of structural range. YooK intercepts these on the fly:
- **Short Conditional Jumps (`0x70–0x7F`)** $\rightarrow$ Upgraded to 6-byte Near Conditional Jumps (`0x0F 0x80–0x8F`).
- **Short Unconditional Jumps (`0xEB`)** $\rightarrow$ Upgraded to 5-byte Near Jumps (`0xE9`).

### 4. Insulated ModR/M RIP-Relative Reconstruction (x64)
Modern x64 compilers heavily utilize RIP-relative data displacements in function prologues (e.g., `mov rcx, [rip + 0x1234]`). YooK features a surgical byte-scanner that identifies the exact ModR/M signature (`0xC7 == 0x05`) for these instructions, automatically calculating and rewriting the displacement offsets inside the trampoline to maintain perfect data integrity.

### 5. Infinite Recursive Trampoline Peeling
When target execution paths are already hooked by incremental linking thunks or third-party overlays, typical hooking engines corrupt the byte sequence. YooK recursively extracts and follows the displacement math of `0xE9`, `0xEB`, and `0xFF 25` instructions, peeling away existing abstraction wrappers until it identifies the actual bedrock target address.

---

## ⚠️ Bottlenecks & Technical Constraints

YooK is engineered specifically for internal runtimes targeting clean, highly optimized binary modules. Due to its reliance on physical hardware traps, it carries the following hard constraints:

* **Windows User-Mode Only:** Works on Windows user mode via Vectored Exception Handling (`RtlAddVectoredExceptionHandler`).
* **User-Mode Debugger Collisions:** Because YooK actively hijacks the CPU's hardware Trap Flag (`EFLAGS.TF`), external user-mode debuggers (such as `x64dbg` or Visual Studio debugger step-in) may intercept the single-step exception.
* **Obfuscated & Packed Binaries:** Commercial software protectors (VMProtect, Themida) intentionally inject fake page faults, anti-debugging single-step checks, and broken stack pointers into function prologues.
* **Microsecond First-Call Latency:** The absolute first invocation of a hooked function triggers single-step exceptions where the thread drops into hardware tracing mode (< 1ms). Subsequent calls execute as direct inline jumps with zero overhead.

---

## 🚀 Integration Showcase

```cpp
#include <iostream>
#include "YooK.hpp"

// 1. Mock target function to instrument
__declspec(noinline) int TargetFunction(int a, int b)
{
    std::cout << "[Target] Original called with: " << a << " + " << b << "\n";
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
    // 3. Initialize YooK hook context
    YooK::Hook myHook(reinterpret_cast<void*>(&TargetFunction), reinterpret_cast<void*>(&DetourFunction));

    // 4. Arm the hardware exception loop
    auto result = myHook.enable();
    if (!result.has_value())
    {
        std::cerr << "[-] Failed to enable hook!\n";
        return -1;
    }

    // 5. First call trips the guard, triggers single-stepping, and hot-patches dynamically
    int res1 = TargetFunction(5, 5); // Output: [Detour] Intercepted call! (returns 100)

    // 6. Subsequent calls route with zero overhead directly into detour
    int res2 = TargetFunction(2, 3); // Output: [Detour] Intercepted call! (returns 50)

    // 7. Call original function via relocated trampoline
    auto original = reinterpret_cast<int(*)(int, int)>(myHook.getTrampoline());
    if (original)
    {
        int origRes = original(5, 5); // Output: [Target] Original called: 5 + 5 (returns 10)
    }

    // 8. Clean up (Transient VEH unregisters automatically)
    myHook.disable();
    int res3 = TargetFunction(5, 5); // Output: [Target] Original called: 5 + 5 (returns 10)

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
