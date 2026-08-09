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

#pragma once
#include <cstdint>
#include <vector>

#if __cplusplus >= 202302L
    #include <expected>
#else
    // C++20 backward compability
    namespace std 
    {
        template <typename T, typename E>
        class expected {
            bool m_hasValue;
            E m_error;
        public:
            constexpr expected() : m_hasValue(true), m_error{} {}
            constexpr expected(E error) : m_hasValue(false), m_error(error) {}
            constexpr bool has_value() const noexcept { return m_hasValue; }
            constexpr E error() const noexcept { return m_error; }
        };

        template <typename E>
        constexpr expected<void, E> unexpected(E error) { return expected<void, E>(error); }
    }
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace YooK
{
    enum class HookError
    {
        VirtualProtectFailed,
        AllocFailed,
        VehRegFailed,
        AlreadyHooked
    };

    enum class HookStatus
    {
        Idle,
        Calculating,
        Hooked,
        ErrorUnsupportedPrologue,
        ErrorAllocFailed
    };
    
    class Hook
    {
        private:
            void* m_target{ nullptr };
            void* m_detour{ nullptr };
            void* m_trampoline{ nullptr };

            std::vector<uint8_t> m_originalBytes;
            std::size_t m_stolenBytes{ 0 };
            std::size_t m_trampBytes{ 0 }; // NEW: Independent trampoline write cursor

            DWORD oldProtection{ 0 };
            bool m_enabled{ false };
            HookStatus m_status{ HookStatus::Idle };

            static auto CALLBACK exception_handler(PEXCEPTION_POINTERS exceptionInfo) noexcept -> LONG;

        public:
            Hook(const Hook&) = delete;
            Hook& operator=(const Hook&) = delete;

            Hook(Hook&& other) noexcept = default;
            Hook& operator=(Hook&& other) noexcept = default;

            Hook(void* target, void* detour) noexcept;
            ~Hook();

            [[nodiscard]] auto enable() noexcept -> std::expected<void, HookError>;
            [[nodiscard]] auto disable() noexcept -> std::expected<void, HookError>;

            [[nodiscard]] auto isEnabled() const noexcept -> bool { return m_enabled; }
            [[nodiscard]] auto getStatus() const noexcept -> HookStatus { return m_status; }
            [[nodiscard]] auto getTrampoline() const noexcept -> void* { return m_trampoline; }
            [[nodiscard]] auto getTarget() const noexcept -> void* { return m_target; }
    };
}