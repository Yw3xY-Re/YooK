/*
 * =========================================================================================
 * Copyright (C) 2026 Yw3xY-Re. All rights reserved.
 * =========================================================================================
 * 
 * This software, its associated source code, and its architectural methodologies 
 * are strictly proprietary and constitute the intellectual property of the author.
 * 
 * 1. Unauthorized reproduction, modification, distribution, or commercial use 
 *    of this framework, in whole or in part, without explicit permission is 
 *    strictly prohibited.
 * 2. The removal, obfuscation, or modification of this copyright header is a 
 *    direct violation of the author's intellectual property rights and is 
 *    actionable under applicable copyright laws.
 * 3. Renaming this file, altering the core namespace designation ('YooK'), or 
 *    modifying structural metadata to obscure its original authorship or origin 
 *    is strictly prohibited.
 * 4. By accessing, viewing, or compiling this source file, you explicitly 
 *    agree to be bound by these terms.
 * 
 * =========================================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include "YooK.hpp"

// Instruction Definitions

// x86 / x64 Opcode Constants
#define X86_OPCODE_JMP_NEAR         0xE9
#define X86_OPCODE_JMP_SHORT        0xEB
#define X86_OPCODE_CALL_NEAR        0xE8
#define X86_OPCODE_ESCAPE_2BYTE     0x0F
#define X86_OPCODE_GRP5             0xFF
#define X86_OPCODE_NOP              0x90

// x86 / x64 ModR/M and Sub-Opcode Identifiers
#define X86_MODRM_JMP_INDIRECT      0x25
#define X86_MODRM_RIP_MASK          0xC7
#define X86_MODRM_RIP_MATCH         0x05

// x86 / x64 Conditional Jump Step Bounds
#define X86_SHORT_COND_JMP_BASE     0x70
#define X86_SHORT_COND_JMP_MAX      0x7F
#define X86_NEAR_COND_JMP_BASE      0x80
#define X86_NEAR_COND_JMP_MAX       0x8F

// x64 Instruction Legacy & REX Prefix Tables
#define X64_REX_PREFIX_BASE         0x40
#define X64_REX_PREFIX_MAX          0x4F
#define X86_PREFIX_OPERAND_SIZE     0x66
#define X86_PREFIX_ADDRESS_SIZE     0x67
#define X86_PREFIX_LOCK             0xF0
#define X86_PREFIX_REPNE            0xF2
#define X86_PREFIX_REPE             0xF3

// ARM64 Binary Instruction Structures
#define ARM64_INS_LDR_X16_PC8       0x58000050 // LDR X16, [PC, #8]
#define ARM64_INS_BR_X16            0xD61F0200 // BR X16
#define ARM64_INS_B_BASE            0x14000000 // B (Immediate) baseline opcode
#define ARM64_OFFSET_MASK_26BIT     0x3FFFFFF  // Sign-extended 26-bit branch mask

// Processor Flag Bitmasks
#define EFLAGS_TRAP_FLAG            0x100      // Trap Flag (TF) control bit for single-stepping

// =========================================================================================

#if !defined(_M_ARM64)
// Architecture abstraction for Intel/AMD execution contexts
#ifdef _WIN64
    #define XIP Rip
#else
    #define XIP Eip
#endif

static std::vector<YooK::Hook*> g_hookRegistry;
static SRWLOCK g_registryLock = SRWLOCK_INIT;
static void* g_vehHandle = nullptr;
#endif

namespace YooK
{
#ifdef _WIN64
    static auto AllocNearby(void* target, size_t size) noexcept -> void*
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        uintptr_t targetAddr = reinterpret_cast<uintptr_t>(target);
        uintptr_t minAddr = targetAddr > 0x7FFF0000 ? targetAddr - 0x7FFF0000 : reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
        uintptr_t maxAddr = (UINTPTR_MAX - targetAddr > 0x7FFF0000) ? targetAddr + 0x7FFF0000 : reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
        uintptr_t searchAddr = minAddr & ~(static_cast<uintptr_t>(si.dwPageSize) - 1);
    
        while (searchAddr < maxAddr)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(reinterpret_cast<void*>(searchAddr), &mbi, sizeof(mbi))) [[unlikely]] break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
            {
                void* allocated = VirtualAlloc(mbi.BaseAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (allocated) return allocated;
            }
            searchAddr += mbi.RegionSize;
        }
        return nullptr;
    }
#endif

    Hook::Hook(void* target, void* detour) noexcept : m_target(target), m_detour(detour) {}

    Hook::~Hook() 
        { auto _ = disable(); }

    auto Hook::enable() noexcept -> std::expected<void, HookError>
    {
        if (m_enabled) [[unlikely]] return std::unexpected(HookError::AlreadyHooked);

#if defined(_M_ARM64)
        uintptr_t src = reinterpret_cast<uintptr_t>(m_target);
        uintptr_t dst = reinterpret_cast<uintptr_t>(m_detour);
        ptrdiff_t delta = static_cast<ptrdiff_t>(dst - src);

        bool isNearBranch = (delta >= -134217728 && delta <= 134217724);
        m_stolenBytes = isNearBranch ? 4 : 16;
        m_trampBytes = m_stolenBytes + 16; 

        m_originalBytes.resize(m_stolenBytes);
        std::memcpy(m_originalBytes.data(), m_target, m_stolenBytes);

        m_trampoline = VirtualAlloc(nullptr, m_trampBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!m_trampoline) [[unlikely]] return std::unexpected(HookError::AllocFailed);

        uint8_t* trampBytes = reinterpret_cast<uint8_t*>(m_trampoline);
        std::memcpy(trampBytes, m_originalBytes.data(), m_stolenBytes);
        
        uintptr_t retAddr = src + m_stolenBytes;
        uint32_t* trampBranch = reinterpret_cast<uint32_t*>(trampBytes + m_stolenBytes);
        trampBranch[0] = ARM64_INS_LDR_X16_PC8;
        trampBranch[1] = ARM64_INS_BR_X16;
        std::memcpy(&trampBranch[2], &retAddr, sizeof(retAddr));

        DWORD patchProtect;
        if (!VirtualProtect(m_target, m_stolenBytes, PAGE_EXECUTE_READWRITE, &patchProtect)) [[unlikely]]
            return std::unexpected(HookError::VirtualProtectFailed);
        
        uint32_t* patchArea = reinterpret_cast<uint32_t*>(m_target);
        if (m_stolenBytes == 4) 
        {
            uint32_t offsetMask = (static_cast<uint32_t>(delta >> 2) & ARM64_OFFSET_MASK_26BIT);
            reinterpret_cast<volatile uint32_t*>(patchArea)[0] = ARM64_INS_B_BASE | offsetMask;
        } 
        else 
        {
            *reinterpret_cast<volatile uintptr_t*>(&patchArea[2]) = dst;
            reinterpret_cast<volatile uint32_t*>(patchArea)[1] = ARM64_INS_BR_X16;
            MemoryBarrier();
            reinterpret_cast<volatile uint32_t*>(patchArea)[0] = ARM64_INS_LDR_X16_PC8;
        }

        VirtualProtect(m_target, m_stolenBytes, patchProtect, &patchProtect);
        FlushInstructionCache(GetCurrentProcess(), m_trampoline, m_trampBytes);
        FlushInstructionCache(GetCurrentProcess(), m_target, m_stolenBytes);

        m_enabled = true;
        m_status = HookStatus::Hooked;
        return {};
#else
        // x86 / x64 unconditional branch chasing
        while (true)
        {
            uint8_t* currentCode = reinterpret_cast<uint8_t*>(m_target);

            if (currentCode[0] == X86_OPCODE_JMP_NEAR)
            {
                uint32_t relativeOffset = *reinterpret_cast<uint32_t*>(&currentCode[1]);
                m_target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_target) + 5 + relativeOffset);
                continue; 
            }
            else if (currentCode[0] == X86_OPCODE_JMP_SHORT)
            {
                int8_t shortOffset = *reinterpret_cast<int8_t*>(&currentCode[1]);
                m_target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_target) + 2 + shortOffset);
                continue;
            }
            else if (currentCode[0] == X86_OPCODE_GRP5 && currentCode[1] == X86_MODRM_JMP_INDIRECT)
            {
#ifdef _WIN64
                uint32_t ripOffset = *reinterpret_cast<uint32_t*>(&currentCode[2]);
                uintptr_t pointerLocation = reinterpret_cast<uintptr_t>(m_target) + 6 + ripOffset;
#else
                uintptr_t pointerLocation = *reinterpret_cast<uintptr_t*>(&currentCode[2]);
#endif
                m_target = *reinterpret_cast<void**>(pointerLocation);
                continue;
            }
            break;
        }

        AcquireSRWLockExclusive(&g_registryLock);
        g_hookRegistry.push_back(this);
        ReleaseSRWLockExclusive(&g_registryLock);

        if (!g_vehHandle) {
            g_vehHandle = AddVectoredExceptionHandler(1, exception_handler);
            if (!g_vehHandle) [[unlikely]] return std::unexpected(HookError::VehRegFailed);
        }

        if (!VirtualProtect(m_target, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection)) [[unlikely]]
        {
            AcquireSRWLockExclusive(&g_registryLock);
            std::erase(g_hookRegistry, this);
            ReleaseSRWLockExclusive(&g_registryLock);
            return std::unexpected(HookError::VirtualProtectFailed);
        }

        m_enabled = true;
        m_status = HookStatus::Calculating;
        m_stolenBytes = 0;
        m_trampBytes = 0;
        return{};
#endif
    }

    auto Hook::disable() noexcept -> std::expected<void, HookError>
    {
        if (!m_enabled) [[unlikely]] return{};

        if (m_status == HookStatus::Hooked && !m_originalBytes.empty()) [[likely]]
        {
            DWORD tempProtect;
            VirtualProtect(m_target, m_stolenBytes, PAGE_EXECUTE_READWRITE, &tempProtect);
            std::memcpy(m_target, m_originalBytes.data(), m_stolenBytes);
            VirtualProtect(m_target, m_stolenBytes, tempProtect, &tempProtect);
        }

        if (m_trampoline) [[likely]]
            { VirtualFree(m_trampoline, 0, MEM_RELEASE); m_trampoline = nullptr; }

#if !defined(_M_ARM64)
        AcquireSRWLockExclusive(&g_registryLock);
        std::erase(g_hookRegistry, this);
        
        // If no hooks remain, unregister from Windows entirely
        if (g_hookRegistry.empty() && g_vehHandle) [[likely]]
        {
            RemoveVectoredExceptionHandler(g_vehHandle);
            g_vehHandle = nullptr;
        }
        ReleaseSRWLockExclusive(&g_registryLock);
#endif
        m_enabled = false;
        m_status = HookStatus::Idle;
        return{};
    }

#if !defined(_M_ARM64)
    auto Hook::exception_handler(PEXCEPTION_POINTERS exceptionInfo) noexcept -> LONG
    {
        const auto exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
        const auto context = exceptionInfo->ContextRecord;

        if (exceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            for (auto* hookInstance : g_hookRegistry)
            {
                if (reinterpret_cast<void*>(context->XIP) == hookInstance->m_target)
                {
                    hookInstance->m_stolenBytes = 0;
                    hookInstance->m_trampBytes = 0;

                    // 48 bytes secures space for instruction bloat (upgrading 2b jumps to 6b)
#ifdef _WIN64
                    hookInstance->m_trampoline = AllocNearby(hookInstance->m_target, 48);
#else
                    hookInstance->m_trampoline = VirtualAlloc(nullptr, 48, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
                    if (!hookInstance->m_trampoline) [[unlikely]] 
                    {
                        hookInstance->m_status = HookStatus::ErrorAllocFailed;
                        return EXCEPTION_CONTINUE_SEARCH;
                    }

                    DWORD temp;
                    VirtualProtect(hookInstance->m_target, 1, PAGE_EXECUTE_READ, &temp);
                    context->EFlags |= EFLAGS_TRAP_FLAG; 
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        if (exceptionCode == STATUS_SINGLE_STEP)
        {
            YooK::Hook* activeHook = nullptr;
            for (auto* hookInstance : g_hookRegistry) {
                if (hookInstance->m_status == HookStatus::Calculating) {
                    activeHook = hookInstance;
                    break;
                }
            }

            if (!activeHook) return EXCEPTION_CONTINUE_SEARCH;

            uintptr_t currentXip = context->XIP;
            uintptr_t lastInstructionStart = reinterpret_cast<uintptr_t>(activeHook->m_target) + activeHook->m_stolenBytes;
            size_t instructionSize = currentXip - lastInstructionStart;

            if (instructionSize > 15) [[unlikely]]
            {
                activeHook->m_status = HookStatus::ErrorUnsupportedPrologue;
                context->EFlags &= ~EFLAGS_TRAP_FLAG;
                DWORD temp;
                VirtualProtect(activeHook->m_target, 1, activeHook->oldProtection, &temp);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            uint8_t* ins = reinterpret_cast<uint8_t*>(lastInstructionStart);
            uint8_t* trampIns = reinterpret_cast<uint8_t*>(activeHook->m_trampoline) + activeHook->m_trampBytes;
            uint8_t primaryOpcode = ins[0];
            size_t bytesWrittenToTramp = instructionSize;

            // --- The Instruction Branching Upgrade Engine ---
            
            // 1. Upgrade Short Conditional Jumps (0x70-0x7F) -> Near Conditional Jumps (0x0F 0x80-0x8F)
            if (primaryOpcode >= X86_SHORT_COND_JMP_BASE && primaryOpcode <= X86_SHORT_COND_JMP_MAX)
            {
                int8_t originalDisp = *reinterpret_cast<int8_t*>(&ins[1]);
                uintptr_t absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                uintptr_t trampRip = reinterpret_cast<uintptr_t>(trampIns) + 6; // 6-byte instruction
                int32_t correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);

                trampIns[0] = X86_OPCODE_ESCAPE_2BYTE;
                trampIns[1] = X86_NEAR_COND_JMP_BASE + (primaryOpcode - X86_SHORT_COND_JMP_BASE);
                std::memcpy(trampIns + 2, &correctedDisp, sizeof(int32_t));
                bytesWrittenToTramp = 6;
            }
            // 2. Upgrade Short Unconditional JMP (0xEB) -> Near JMP (0xE9)
            else if (primaryOpcode == X86_OPCODE_JMP_SHORT)
            {
                int8_t originalDisp = *reinterpret_cast<int8_t*>(&ins[1]);
                uintptr_t absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                uintptr_t trampRip = reinterpret_cast<uintptr_t>(trampIns) + 5; // 5-byte instruction
                int32_t correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);

                trampIns[0] = X86_OPCODE_JMP_NEAR;
                std::memcpy(trampIns + 1, &correctedDisp, sizeof(int32_t));
                bytesWrittenToTramp = 5;
            }
            // 3. Handle standard instructions and pre-existing near jumps
            else
            {
                std::memcpy(trampIns, ins, instructionSize);

                if (primaryOpcode == X86_OPCODE_CALL_NEAR || primaryOpcode == X86_OPCODE_JMP_NEAR)
                {
                    int32_t originalDisp = *reinterpret_cast<int32_t*>(&ins[1]);
                    uintptr_t absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                    uintptr_t trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                    int32_t correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                    std::memcpy(trampIns + 1, &correctedDisp, sizeof(int32_t));
                }
                else if (primaryOpcode == X86_OPCODE_ESCAPE_2BYTE && (ins[1] >= X86_NEAR_COND_JMP_BASE && ins[1] <= X86_NEAR_COND_JMP_MAX))
                {
                    int32_t originalDisp = *reinterpret_cast<int32_t*>(&ins[2]);
                    uintptr_t absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                    uintptr_t trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                    int32_t correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                    std::memcpy(trampIns + 2, &correctedDisp, sizeof(int32_t));
                }

#ifdef _WIN64
                // x64 ModR/M Data Offset Fixer
                size_t cursor = 0;
                while (cursor < instructionSize) 
                {
                    uint8_t b = ins[cursor];
                    if ((b >= X64_REX_PREFIX_BASE && b <= X64_REX_PREFIX_MAX) || 
                        b == X86_PREFIX_OPERAND_SIZE || b == X86_PREFIX_ADDRESS_SIZE || 
                        b == X86_PREFIX_LOCK || b == X86_PREFIX_REPNE || b == X86_PREFIX_REPE) 
                    {
                        cursor++; continue;
                    }
                    break;
                }
                if (ins[cursor] == X86_OPCODE_ESCAPE_2BYTE) cursor += 2;
                else cursor += 1;

                if (cursor < instructionSize) 
                {
                    uint8_t modrm = ins[cursor];
                    if ((modrm & X86_MODRM_RIP_MASK) == X86_MODRM_RIP_MATCH)
                    {
                        size_t dispOffset = cursor + 1;
                        int32_t originalDisp = *reinterpret_cast<int32_t*>(&ins[dispOffset]);
                        uintptr_t absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                        uintptr_t trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                        int32_t correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                        std::memcpy(trampIns + dispOffset, &correctedDisp, sizeof(int32_t));
                    }
                }
#endif
            }

            activeHook->m_stolenBytes += instructionSize;
            activeHook->m_trampBytes += bytesWrittenToTramp; // Advance independent cursor

            if (activeHook->m_stolenBytes < 5)
            {
                context->EFlags |= EFLAGS_TRAP_FLAG;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // Engine Exit Strategy
            activeHook->m_status = HookStatus::Hooked;
            context->EFlags &= ~EFLAGS_TRAP_FLAG; 

            activeHook->m_originalBytes.resize(activeHook->m_stolenBytes);
            std::memcpy(activeHook->m_originalBytes.data(), activeHook->m_target, activeHook->m_stolenBytes);

            uint8_t* trampBytes = reinterpret_cast<uint8_t*>(activeHook->m_trampoline);
            uintptr_t retAddr = reinterpret_cast<uintptr_t>(activeHook->m_target) + activeHook->m_stolenBytes;
                
#ifdef _WIN64
            // Append jump back using m_trampBytes footprint
            trampBytes[activeHook->m_trampBytes] = X86_OPCODE_GRP5;
            trampBytes[activeHook->m_trampBytes + 1] = X86_MODRM_JMP_INDIRECT;
            std::memset(&trampBytes[activeHook->m_trampBytes + 2], 0, 4); 
            std::memcpy(&trampBytes[activeHook->m_trampBytes + 6], &retAddr, sizeof(retAddr));
#else
            uintptr_t trampSrc = reinterpret_cast<uintptr_t>(trampBytes + activeHook->m_trampBytes);
            uint32_t trampRelativeOffset = static_cast<uint32_t>(retAddr - (trampSrc + 5));
            trampBytes[activeHook->m_trampBytes] = X86_OPCODE_JMP_NEAR;
            std::memcpy(&trampBytes[activeHook->m_trampBytes + 1], &trampRelativeOffset, 4);
#endif

            // Atomic Hot-Patch
            DWORD patchProtect;
            size_t protectSize = (activeHook->m_stolenBytes > 8) ? activeHook->m_stolenBytes : 8;
            VirtualProtect(activeHook->m_target, protectSize, PAGE_EXECUTE_READWRITE, &patchProtect);

            uintptr_t src = reinterpret_cast<uintptr_t>(activeHook->m_target);
            uintptr_t dst = reinterpret_cast<uintptr_t>(activeHook->m_detour);
            uint32_t relativeOffset = static_cast<uint32_t>(dst - (src + 5));

            uint64_t originalValue = *reinterpret_cast<volatile uint64_t*>(src);
            while (true)
            {
                uint64_t newValue = originalValue;
                uint8_t* patchBytes = reinterpret_cast<uint8_t*>(&newValue);

                patchBytes[0] = X86_OPCODE_JMP_NEAR; 
                *reinterpret_cast<uint32_t*>(&patchBytes[1]) = relativeOffset;

                for (size_t i = 5; i < activeHook->m_stolenBytes && i < 8; ++i) {
                    patchBytes[i] = X86_OPCODE_NOP;
                }

                uint64_t oldCheck = InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(src),
                    static_cast<LONG64>(newValue),
                    static_cast<LONG64>(originalValue)
                );

                if (oldCheck == originalValue) break;
                originalValue = oldCheck;
            }

            if (activeHook->m_stolenBytes > 8) [[unlikely]]
                std::memset(reinterpret_cast<void*>(src + 8), X86_OPCODE_NOP, activeHook->m_stolenBytes - 8);

            VirtualProtect(activeHook->m_target, protectSize, patchProtect, &patchProtect);
            FlushInstructionCache(GetCurrentProcess(), activeHook->m_target, activeHook->m_stolenBytes);

            // VEH destruction
            AcquireSRWLockExclusive(&g_registryLock);
            bool anyStillCalculating = std::any_of(g_hookRegistry.begin(), g_hookRegistry.end(), [](YooK::Hook* h) 
            {
                return h->getStatus() == HookStatus::Calculating;
            });

            if (!anyStillCalculating && g_vehHandle) [[likely]]
            {
                RemoveVectoredExceptionHandler(g_vehHandle);
                g_vehHandle = nullptr;
            }
            ReleaseSRWLockExclusive(&g_registryLock);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
#endif
}