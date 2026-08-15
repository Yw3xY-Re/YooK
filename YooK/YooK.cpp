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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstring>
#include <algorithm>
#include "YooK.hpp"
#include "Y3lib/include/Y3lib/Memory/Allocator/Container/Vector.hpp"
#include "Y3lib/include/Y3lib/EatTraversal/ntdll/syscalls/Syscalls.h"
#include "Y3lib/include/Y3lib/EatTraversal/ntdll/ntdll.hpp"
#include "Y3lib/include/Y3lib/Memory/Allocator/Allocator.hpp"

// Instruction Definitions (x64 Specialized)

#define X86_OPCODE_JMP_NEAR         0xE9
#define X86_OPCODE_JMP_SHORT        0xEB
#define X86_OPCODE_CALL_NEAR        0xE8
#define X86_OPCODE_ESCAPE_2BYTE     0x0F
#define X86_OPCODE_GRP5             0xFF
#define X86_OPCODE_NOP              0x90

// x64 ModR/M and Sub-Opcode Identifiers
#define X86_MODRM_JMP_INDIRECT      0x25
#define X86_MODRM_RIP_MASK          0xC7
#define X86_MODRM_RIP_MATCH         0x05

// x64 Conditional Jump Step Bounds
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

// Processor Flag Bitmasks
#define EFLAGS_TRAP_FLAG            0x100      // Trap Flag (TF) control bit for single-stepping

// =========================================================================================

namespace YooK
{
    struct Hook::Impl
    {
        void* m_target{ nullptr };
        void* m_detour{ nullptr };
        void* m_trampoline{ nullptr };

        Y3lib::Memory::vector<uint8_t> m_originalBytes;
        std::size_t m_stolenBytes{ 0 };
        std::size_t m_trampBytes{ 0 };

        DWORD oldProtection{ 0 };
        bool m_enabled{ false };
        HookStatus m_status{ HookStatus::Idle };

        Impl(void* target, void* detour) noexcept : m_target(target), m_detour(detour) {}

        static void* operator new(size_t size) noexcept
        {
            return Y3lib::Memory::Allocator::Instance().AllocateFast(size);
        }

        static void operator delete(void* ptr) noexcept
        {
            Y3lib::Memory::Allocator::Instance().FreeFast(ptr);
        }
    };
}

namespace 
{
    Y3lib::Memory::vector<YooK::Hook::Impl*> g_hookRegistry;
    SRWLOCK g_registryLock = SRWLOCK_INIT;
    void* g_vehHandle = nullptr;

    auto CALLBACK exception_handler(PEXCEPTION_POINTERS exceptionInfo) noexcept -> LONG;

    // Direct dynamic VEH Registration via RtlAddVectoredExceptionHandler / Pointer Encoding
    typedef PVOID (NTAPI *pfnRtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
    typedef ULONG (NTAPI *pfnRtlRemoveVectoredExceptionHandler)(PVOID Handle);

    [[nodiscard]] void* StealthRegisterVEH(PVECTORED_EXCEPTION_HANDLER pHandler) noexcept
    {
        auto& table = Y3lib::ntdll::Table();
        if (table.RtlAddVectoredExceptionHandler)
        {
            auto pfnAdd = reinterpret_cast<pfnRtlAddVectoredExceptionHandler>(table.RtlAddVectoredExceptionHandler);
            return pfnAdd(1, pHandler);
        }

        return AddVectoredExceptionHandler(1, pHandler);
    }

    void StealthUnregisterVEH(void* hVeh) noexcept
    {
        if (!hVeh) return;

        auto& table = Y3lib::ntdll::Table();
        if (table.RtlRemoveVectoredExceptionHandler)
        {
            auto pfnRemove = reinterpret_cast<pfnRtlRemoveVectoredExceptionHandler>(table.RtlRemoveVectoredExceptionHandler);
            pfnRemove(hVeh);
            return;
        }

        RemoveVectoredExceptionHandler(hVeh);
    }

    auto AllocNearby(void* target, size_t size) noexcept -> void*
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        auto targetAddr = reinterpret_cast<uintptr_t>(target);
        auto minAddr = targetAddr > 0x7FFF0000 ? targetAddr - 0x7FFF0000 : reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
        uintptr_t maxAddr = (UINTPTR_MAX - targetAddr > 0x7FFF0000) ? targetAddr + 0x7FFF0000 : reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
        auto searchAddr = minAddr & ~(static_cast<uintptr_t>(si.dwPageSize) - 1);
    
        while (searchAddr < maxAddr)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (Syscall_QueryVirtualMemory(reinterpret_cast<void*>(searchAddr), 0, &mbi, sizeof(mbi), nullptr, g_SyscallTable) != 0) [[unlikely]] break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
            {
                void* allocated = Y3lib::Memory::Allocator::Instance().AllocateFast(size, (HANDLE)-1, PAGE_READWRITE, ALLOC_FLAG_FORCE_VIRTUAL, mbi.BaseAddress);
                if (allocated) return allocated;
            }
            searchAddr += mbi.RegionSize;
        }
        return nullptr;
    }
}

namespace YooK
{
    Hook::Hook(void* target, void* detour) noexcept : m_impl(std::make_unique<Impl>(target, detour)) {}

    Hook::~Hook() { auto _ = disable(); }

    Hook::Hook(Hook&& other) noexcept = default;
    Hook& Hook::operator=(Hook&& other) noexcept = default;

    auto Hook::isEnabled() const noexcept -> bool { return m_impl ? m_impl->m_enabled : false; }
    auto Hook::getStatus() const noexcept -> HookStatus { return m_impl ? m_impl->m_status : HookStatus::Idle; }
    auto Hook::getTrampoline() const noexcept -> void* { return m_impl ? m_impl->m_trampoline : nullptr; }
    auto Hook::getTarget() const noexcept -> void* { return m_impl ? m_impl->m_target : nullptr; }

    auto Hook::enable() noexcept -> std::expected<void, HookError>
    {
        if (!m_impl || m_impl->m_enabled) [[unlikely]] return std::unexpected(HookError::AlreadyHooked);

        // x64 unconditional branch chasing
        while (true)
        {
            auto currentCode = reinterpret_cast<uint8_t*>(m_impl->m_target);

            if (currentCode[0] == X86_OPCODE_JMP_NEAR)
            {
                auto relativeOffset = *reinterpret_cast<uint32_t*>(&currentCode[1]);
                m_impl->m_target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_impl->m_target) + 5 + relativeOffset);
                continue; 
            }
            else if (currentCode[0] == X86_OPCODE_JMP_SHORT)
            {
                auto shortOffset = *reinterpret_cast<int8_t*>(&currentCode[1]);
                m_impl->m_target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_impl->m_target) + 2 + shortOffset);
                continue; 
            }
            else if (currentCode[0] == X86_OPCODE_GRP5 && currentCode[1] == X86_MODRM_JMP_INDIRECT)
            {
                auto ripOffset = *reinterpret_cast<uint32_t*>(&currentCode[2]);
                auto pointerLocation = reinterpret_cast<uintptr_t>(m_impl->m_target) + 6 + ripOffset;
                m_impl->m_target = *reinterpret_cast<void**>(pointerLocation);
                continue;
            }
            break;
        }

        AcquireSRWLockExclusive(&g_registryLock);
        g_hookRegistry.push_back(m_impl.get());
        ReleaseSRWLockExclusive(&g_registryLock);

        if (!g_vehHandle) 
        {
            g_vehHandle = StealthRegisterVEH(exception_handler);
            if (!g_vehHandle) [[unlikely]] return std::unexpected(HookError::VehRegFailed);
        }

        if (!Y3lib::Memory::Allocator::Instance().Protect(m_impl->m_target, 1, PAGE_EXECUTE_READ | PAGE_GUARD, m_impl->oldProtection)) [[unlikely]]
        {
            AcquireSRWLockExclusive(&g_registryLock);
            std::erase(g_hookRegistry, m_impl.get());
            ReleaseSRWLockExclusive(&g_registryLock);
            return std::unexpected(HookError::VirtualProtectFailed);
        }

        m_impl->m_enabled = true;
        m_impl->m_status = HookStatus::Calculating;
        m_impl->m_stolenBytes = 0;
        m_impl->m_trampBytes = 0;
        return{};
    }

    auto Hook::disable() noexcept -> std::expected<void, HookError>
    {
        if (!m_impl || !m_impl->m_enabled) [[unlikely]] return{};

        if (m_impl->m_status == HookStatus::Hooked && !m_impl->m_originalBytes.empty()) [[likely]]
        {
            DWORD tempProtect, temp2;
            (void)Y3lib::Memory::Allocator::Instance().Protect(m_impl->m_target, m_impl->m_stolenBytes, PAGE_READWRITE, tempProtect);
            std::memcpy(m_impl->m_target, m_impl->m_originalBytes.data(), m_impl->m_stolenBytes);
            (void)Y3lib::Memory::Allocator::Instance().Protect(m_impl->m_target, m_impl->m_stolenBytes, tempProtect, temp2);
        }

        if (m_impl->m_trampoline) [[likely]]
        {
            Y3lib::Memory::Allocator::Instance().FreeFast(m_impl->m_trampoline, 0); 
            m_impl->m_trampoline = nullptr; 
        }

        AcquireSRWLockExclusive(&g_registryLock);
        std::erase(g_hookRegistry, m_impl.get());
        
        // If no hooks remain, unregister VEH
        if (g_hookRegistry.empty() && g_vehHandle) [[likely]]
        {
            StealthUnregisterVEH(g_vehHandle);
            g_vehHandle = nullptr;
        }
        ReleaseSRWLockExclusive(&g_registryLock);

        m_impl->m_enabled = false;
        m_impl->m_status = HookStatus::Idle;
        return{};
    }
}

namespace
{
    auto CALLBACK exception_handler(PEXCEPTION_POINTERS exceptionInfo) noexcept -> LONG
    {
        const auto exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
        const auto context = exceptionInfo->ContextRecord;

        if (exceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            for (auto* hookInstance : g_hookRegistry)
            {
                if (reinterpret_cast<void*>(context->Rip) == hookInstance->m_target)
                {
                    hookInstance->m_stolenBytes = 0;
                    hookInstance->m_trampBytes = 0;

                    // 48 bytes secures space for instruction bloat (upgrading 2b jumps to 6b)
                    hookInstance->m_trampoline = AllocNearby(hookInstance->m_target, 48);
                    if (!hookInstance->m_trampoline) [[unlikely]] 
                    {
                        hookInstance->m_status = YooK::HookStatus::ErrorAllocFailed;
                        return EXCEPTION_CONTINUE_SEARCH;
                    }

                    DWORD temp;
                    (void)Y3lib::Memory::Allocator::Instance().Protect(hookInstance->m_target, 1, PAGE_EXECUTE_READ, temp);
                    context->EFlags |= EFLAGS_TRAP_FLAG; 
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        if (exceptionCode == STATUS_SINGLE_STEP)
        {
            YooK::Hook::Impl* activeHook = nullptr;
            for (auto* hookInstance : g_hookRegistry) {
                if (hookInstance->m_status == YooK::HookStatus::Calculating) {
                    activeHook = hookInstance;
                    break;
                }
            }

            if (!activeHook) return EXCEPTION_CONTINUE_SEARCH;

            uintptr_t currentRip = context->Rip;
            auto lastInstructionStart = reinterpret_cast<uintptr_t>(activeHook->m_target) + activeHook->m_stolenBytes;
            size_t instructionSize = currentRip - lastInstructionStart;

            if (instructionSize > 15) [[unlikely]]
            {
                activeHook->m_status = YooK::HookStatus::ErrorUnsupportedPrologue;
                context->EFlags &= ~EFLAGS_TRAP_FLAG;
                DWORD temp;
                (void)Y3lib::Memory::Allocator::Instance().Protect(activeHook->m_target, 1, activeHook->oldProtection, temp);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            auto ins = reinterpret_cast<uint8_t*>(lastInstructionStart);
            auto trampIns = reinterpret_cast<uint8_t*>(activeHook->m_trampoline) + activeHook->m_trampBytes;
            uint8_t primaryOpcode = ins[0];
            size_t bytesWrittenToTramp = instructionSize;
            
            // Upgrade Short Conditional Jumps (0x70-0x7F) -> Near Conditional Jumps (0x0F 0x80-0x8F)
            if (primaryOpcode >= X86_SHORT_COND_JMP_BASE && primaryOpcode <= X86_SHORT_COND_JMP_MAX)
            {
                auto originalDisp = *reinterpret_cast<int8_t*>(&ins[1]);
                auto absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                auto trampRip = reinterpret_cast<uintptr_t>(trampIns) + 6; // 6-byte instruction
                auto correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);

                trampIns[0] = X86_OPCODE_ESCAPE_2BYTE;
                trampIns[1] = X86_NEAR_COND_JMP_BASE + (primaryOpcode - X86_SHORT_COND_JMP_BASE);
                std::memcpy(trampIns + 2, &correctedDisp, sizeof(int32_t));
                bytesWrittenToTramp = 6;
            }
            // Upgrade Short Unconditional JMP (0xEB) -> Near JMP (0xE9)
            else if (primaryOpcode == X86_OPCODE_JMP_SHORT)
            {
                auto originalDisp = *reinterpret_cast<int8_t*>(&ins[1]);
                auto absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                auto trampRip = reinterpret_cast<uintptr_t>(trampIns) + 5; // 5-byte instruction
                auto correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);

                trampIns[0] = X86_OPCODE_JMP_NEAR;
                std::memcpy(trampIns + 1, &correctedDisp, sizeof(int32_t));
                bytesWrittenToTramp = 5;
            }
            // Handle standard instructions and pre-existing near jumps
            else
            {
                std::memcpy(trampIns, ins, instructionSize);

                if (primaryOpcode == X86_OPCODE_CALL_NEAR || primaryOpcode == X86_OPCODE_JMP_NEAR)
                {
                    auto originalDisp = *reinterpret_cast<int32_t*>(&ins[1]);
                    auto absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                    auto trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                    auto correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                    std::memcpy(trampIns + 1, &correctedDisp, sizeof(int32_t));
                }
                else if (primaryOpcode == X86_OPCODE_ESCAPE_2BYTE && (ins[1] >= X86_NEAR_COND_JMP_BASE && ins[1] <= X86_NEAR_COND_JMP_MAX))
                {
                    auto originalDisp = *reinterpret_cast<int32_t*>(&ins[2]);
                    auto absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                    auto trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                    auto correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                    std::memcpy(trampIns + 2, &correctedDisp, sizeof(int32_t));
                }

                // x64 ModR/M Data Offset Fixer
                size_t cursor = 0;
                while (cursor < instructionSize) 
                {
                    auto b = ins[cursor];
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
                    auto modrm = ins[cursor];
                    if ((modrm & X86_MODRM_RIP_MASK) == X86_MODRM_RIP_MATCH)
                    {
                        size_t dispOffset = cursor + 1;
                        auto originalDisp = *reinterpret_cast<int32_t*>(&ins[dispOffset]);
                        auto absoluteTarget = lastInstructionStart + instructionSize + originalDisp;
                        auto trampRip = reinterpret_cast<uintptr_t>(trampIns) + instructionSize;
                        auto correctedDisp = static_cast<int32_t>(absoluteTarget - trampRip);
                        std::memcpy(trampIns + dispOffset, &correctedDisp, sizeof(int32_t));
                    }
                }
            }

            activeHook->m_stolenBytes += instructionSize;
            activeHook->m_trampBytes += bytesWrittenToTramp;

            if (activeHook->m_stolenBytes < 5)
            {
                context->EFlags |= EFLAGS_TRAP_FLAG;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // Engine Exit Strategy
            activeHook->m_status = YooK::HookStatus::Hooked;
            context->EFlags &= ~EFLAGS_TRAP_FLAG; 

            activeHook->m_originalBytes.resize(activeHook->m_stolenBytes);
            std::memcpy(activeHook->m_originalBytes.data(), activeHook->m_target, activeHook->m_stolenBytes);

            auto trampBytes = reinterpret_cast<uint8_t*>(activeHook->m_trampoline);
            auto retAddr = reinterpret_cast<uintptr_t>(activeHook->m_target) + activeHook->m_stolenBytes;
                
            // Append 14-byte 64-bit indirect jump back: JMP [RIP+0] -> retAddr
            trampBytes[activeHook->m_trampBytes] = X86_OPCODE_GRP5;
            trampBytes[activeHook->m_trampBytes + 1] = X86_MODRM_JMP_INDIRECT;
            std::memset(&trampBytes[activeHook->m_trampBytes + 2], 0, 4); 
            std::memcpy(&trampBytes[activeHook->m_trampBytes + 6], &retAddr, sizeof(retAddr));

            // Transition trampoline from PAGE_READWRITE to PAGE_EXECUTE_READ once complete
            DWORD trampOldProtect;
            size_t totalTrampSize = activeHook->m_trampBytes + 14;
            (void)Y3lib::Memory::Allocator::Instance().Protect(activeHook->m_trampoline, totalTrampSize, PAGE_EXECUTE_READ, trampOldProtect);
            (void)Syscall_FlushInstructionCache((HANDLE)-1, activeHook->m_trampoline, totalTrampSize, g_SyscallTable);

            // Atomic 8-byte Hot-Patch
            DWORD patchProtect;
            size_t protectSize = (activeHook->m_stolenBytes > 8) ? activeHook->m_stolenBytes : 8;
            (void)Y3lib::Memory::Allocator::Instance().Protect(activeHook->m_target, protectSize, PAGE_READWRITE, patchProtect);

            auto src = reinterpret_cast<uintptr_t>(activeHook->m_target);
            auto dst = reinterpret_cast<uintptr_t>(activeHook->m_detour);
            auto relativeOffset = static_cast<uint32_t>(dst - (src + 5));

            auto originalValue = *reinterpret_cast<volatile uint64_t*>(src);
            while (true)
            {
                auto newValue = originalValue;
                auto patchBytes = reinterpret_cast<uint8_t*>(&newValue);

                patchBytes[0] = X86_OPCODE_JMP_NEAR; 
                *reinterpret_cast<uint32_t*>(&patchBytes[1]) = relativeOffset;

                for (size_t i = 5; i < activeHook->m_stolenBytes && i < 8; ++i) 
                { patchBytes[i] = X86_OPCODE_NOP; }

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

            DWORD tempProtect2;
            (void)Y3lib::Memory::Allocator::Instance().Protect(activeHook->m_target, protectSize, patchProtect, tempProtect2);
            (void)Syscall_FlushInstructionCache((HANDLE)-1, activeHook->m_target, activeHook->m_stolenBytes, g_SyscallTable);

            // VEH immediate unregistration upon completion
            AcquireSRWLockExclusive(&g_registryLock);
            bool anyStillCalculating = std::any_of(g_hookRegistry.begin(), g_hookRegistry.end(), [](YooK::Hook::Impl* h) 
            {
                return h->m_status == YooK::HookStatus::Calculating;
            });

            if (!anyStillCalculating && g_vehHandle) [[likely]]
            {
                StealthUnregisterVEH(g_vehHandle);
                g_vehHandle = nullptr;
            }
            ReleaseSRWLockExclusive(&g_registryLock);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}