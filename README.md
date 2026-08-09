# YooK

An ultra-lightweight (~510 LoC), multi-architecture inline hooking and instrumentation framework for Windows user-mode (x86, x64, ARM64) built in modern C++23 with C++20 backward compatibility. 

---

> **Author Note:** This engine was built entirely from scratch purely out of the desire for a raw, low-level technical challenge. Why copy-paste bloated, thousand-line software disassemblers when you can weaponize the physical silicon registers to do the math for you?

---

## Core Architecture Concept

YooK completely eliminates traditional user-mode Length Disassembler Engines (LDEs). Instead, it uses **hardware-assisted side channels** to turn the physical processor itself into the disassembler.

* **x86/x64 Tracking:** Registers a localized Vectored Exception Handler and arms a `PAGE_GUARD` on the target function prologue. When executed, the VEH captures the fault and flips the CPU Trap Flag (`EFLAGS.TF`). The thread single-steps until a 5-byte relative jump boundary is discovered, constructs the trampoline, hot-patches the prologue, and exits.
* **ARM64 Tracking:** Automatically drops the exception mechanics entirely when compiled for RISC architectures, using the fixed 4-byte instruction width to instantly install synchronous near/far branches safely.
* **Transient OS Footprint:** The exact microsecond the hook calculation finishes and the atomic patch is written, YooK queries its internal state machine. If no other hooks are calculating, it permanently unregisters the VEH handle from the Windows kernel, leaving zero passive registration trails in memory.

---

## The Philosophy: Hardware vs. Software (LDEs)

Most mainstream hooking libraries (e.g., MinHook, Detours, PolyHook) rely on embedded Length Disassembler Engines (LDEs) to calculate instruction boundaries before writing an inline patch. YooK discards this approach entirely. Here is why:

* **Future-Proof Opcode Independence:** Traditional LDEs use massive, hardcoded lookup tables. When a compiler generates a new or complex instruction extension that the LDE's table hasn't mapped, the engine miscalculates the length, slices an instruction in half, and instantly crashes the host process. YooK never parses bytes manually; the physical Intel/AMD silicon inherently knows how to decode its own instructions, making YooK functionally immune to unknown opcode crashes.
* **Drastic Bloat Reduction:** Software disassemblers require thousands of lines of switch-case statements, operand matrices, and prefix evaluators to do their job. By routing the calculation through the native hardware execution flags, YooK achieves the exact same inline jump precision while keeping the entire framework footprint at roughly **510 lines of code**.
* **True Execution Context:** Static disassemblers read dead bytes from memory. YooK evaluates them dynamically during live execution, allowing it to natively sidestep superficial static compiler tricks that easily confuse standard LDEs.

---

## Deep-Dive Feature Breakdown

### 1. Zero Static Signature Footprint
Traditional hooking engines embed heavy decoding tables (like HDE or Zydis) containing massive data blocks to parse opcode prefixes, ModR/M fields, and SIB bytes. Because YooK delegates instruction decoding entirely to the physical CPU via the hardware single-step exception line, it contains zero hardcoded instruction lookup tables, drastically reducing binary bloat and signature footprints.

### 2. Lock-Free Atomic Thread Safety
Unlike legacy engines that use `SuspendThread` to freeze the entire process (causing render pipeline crashes and micro-stutters), YooK applies its final hook via a single-cycle 8-byte hardware bus lock (`InterlockedCompareExchange64`). Global registry writes are insulated by zero-overhead Windows Slim Reader/Writer (SRW) locks. The result is flawless multi-threaded stability without ever pausing background execution.

### 3. Dynamic Conditional Branch Upgrading
When relocating a function prologue to a 48-byte allocated trampoline, 2-byte short jumps frequently break because the destination is now out of structural range. YooK intercepts these on the fly, seamlessly upgrading Short Conditional Jumps (`0x70-0x7F`) into 6-byte Near Conditional Jumps (`0x0F 0x80-0x8F`) and absolute short jumps (`0xEB`) into near jumps (`0xE9`) to guarantee 2 GB of relative reach.

### 4. Insulated ModR/M RIP-Relative Reconstruction
Modern x64 compilers heavily utilize RIP-relative data displacements in function prologues (e.g., `mov rcx, [rip + 0x1234]`). YooK features a surgical byte-scanner that identifies the exact ModR/M signature (`0xC7 == 0x05`) for these instructions, automatically calculating and rewriting the displacement offsets inside the trampoline to maintain perfect data integrity.

### 5. Infinite Recursive Trampoline Peeling
When target execution paths are already hooked by incremental linking thunks or third-party overlays, typical hooking engines corrupt the byte sequence. YooK recursively extracts and follows the displacement math of `0xE9`, `0xEB`, and `0xFF 25` instructions, peeling away existing abstraction wrappers until it identifies the actual bedrock target address.

---

## Bottlenecks & Technical Constraints

YooK is engineered specifically for internal runtimes targeting clean, highly optimized binary modules. Due to its reliance on physical hardware traps, it carries the following hard constraints:

* **Environment Dependent:** Works on Windows **user mode** only due to the usage of Vectored Exception Handling and the WIN32 APIs. Even though it could be ported to other operating systems via signals, the goal of this project is to reduce bloat as much as possible while maintaining the best functionality achievable within the Windows subsystem.
* **User-Mode Debugger Collisions:** Because YooK actively hijacks the CPU's hardware Trap Flag, it is structurally incompatible with external user-mode debuggers. Attempting to step through a hooked target function using `x64dbg` or Visual Studio will result in exception routing collisions between the debugger and the engine, however a crash caused by YooK is very unlikely especially if the target user works on isn't packed or heavily obfuscated.
* **Obfuscated & Packed Memory:** Commercial software protectors (VMProtect, Themida) intentionally inject fake page faults, anti-debugging single-step checks, and broken stack pointers into function prologues. YooK's VEH tracking loop will fail if it encounters these intentional hardware traps.
* **Microsecond First-Call Latency:** The absolute first invocation of a hooked function triggers a sequence of single-step exceptions where the thread drops into hardware tracing mode. While this latency window lasts less than a millisecond, it represents a minor processing delay that only occurs on the very first function execution tick. Practically unnoticeable.

---

## Integration Showcase

Integrating YooK inside a project is clean and direct:

```cpp
#include <iostream>
#include <YooK.hpp>

// A mock target engine function to instrument
__declspec(noinline) void OriginalFunction(int val)
{
    std::cout << "[Target] Original executed with value: " << val << "\n";
}

// Our custom instrumentation detour
void DetourFunction(int val)
{
    std::cout << "[Detour] Intercepted execution context safely, value: " << val << "\n";
}

int main()
{
    // Initialize the YooK context mapping
    YooK::Hook myHook(reinterpret_cast<void*>(OriginalFunction), reinterpret_cast<void*>(DetourFunction));

    // Arm the hardware exception loop
    auto result = myHook.enable();
    if (!result.has_value()) return -1;

    // First call trips the guard, triggers single-stepping, and hot-patches the function dynamically
    OriginalFunction(1337);

    // Second call routes with zero overhead directly into the detour function
    OriginalFunction(42);

    // Clean up the process space (Transient VEH unregisters automatically)
    myHook.disable();
    return 0;
}