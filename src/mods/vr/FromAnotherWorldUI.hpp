#pragma once

// From Another World (UE 5.6.1-44394996, D3D12): recovery of the RHI texture
// allocator call used to create the dedicated Slate UI texture.
//
// The stock UEVR recognizers (uevr::buffered_rt::find_after_name / find_destroy)
// reject this build for two reasons:
//   1. UE5.6 wraps the allocation in two stack "scope" objects, so the hidden
//      result is loaded after two scope destructors rather than immediately.
//   2. The refcount release is an out-of-line helper, not an inline lock-xadd.
//
// This header recognises the exact shape found in the shipping binary, using byte
// patterns (no decoder), and verifies the release helper and FRHIResource::Destroy
// against byte fingerprints read from the module. Everything fails closed.
//
// Allocation function (exe+0x922BB2B):
//   lea  r9,[rbp+X]            ; descriptor
//   mov  rcx,[rip+GDynamicRHI]
//   lea  r8,[rip+CommandList]
//   lea  rdx,[rbp+OUT]         ; hidden result
//   mov  rax,[rcx]
//   call [rax+0x1A8]           ; RHICreateTexture
//   lea  rcx,[rbp+A] ; call scope_dtor_1
//   lea  rcx,[rbp+B] ; call scope_dtor_2
//   mov  rbx,[rsp+S]
//   mov  rax,[rbp+OUT]
// followed by the release of the previous ref:
//   lea  rcx,[rbx+8] ; mov edx,3 ; call release_helper ; test eax,eax ; jns ..
//   jne ..           ; mov rcx,rbx ; call destroy

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>

#include "FromAnotherWorldRHI.hpp"

namespace uevr::from_another_world_ui {

inline constexpr uint8_t variant_id = 1;

struct Proof {
    uintptr_t callsite{};
    uintptr_t receiver_cell{};
    uintptr_t command_list{};
    int64_t output_displacement{};   // rbp-relative
    uint32_t vtable_offset{};
    uint8_t length{};
    std::array<uint8_t, 15> bytes{};
    uintptr_t release_helper{};
    uintptr_t destroy{};
};

// FRHIResource::Destroy in this build (exe+0x5260F10): marks the packed +8 word
// for deferred deletion (bts 30 / lock cmpxchg).
inline constexpr std::array<uint8_t, 0x31> destroy_fingerprint{
    0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0x0f,0x0d,0x49,0x08,
    0x8b,0x41,0x08,
    0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
    0x8b,0xd0,0x0f,0xba,0xea,0x1e,0xf0,0x0f,0xb1,0x51,0x08,0x75,0xf3,
    0x8b,0xf8,0x85,0xc0};

// Refcount release helper (exe+0x35B5780): lock xadd [rcx],-1 with an ensure on
// the sign bit, then masks the count with 0x3fffffff. Same semantics as UEVR's
// own ReleaseTexture (xadd -1; last ref when (previous & 0x3fffffff) == 1).
inline constexpr std::array<uint8_t, 0x13> release_helper_prefix{
    0x40,0x53,0x48,0x83,0xec,0x20,0xbb,0xff,0xff,0xff,0xff,0xf0,0x0f,0xc1,0x19,0x85,0xdb,0x79,0x26};
inline constexpr size_t release_helper_mask_offset = 0x39;
inline constexpr std::array<uint8_t, 6> release_helper_mask{0x81,0xe3,0xff,0xff,0xff,0x3f};

// Emergency switch: set UEVR_FAW_NO_UI_HOOK=1 in the environment to restore the
// previous fail-closed behaviour without rebuilding.
inline bool disabled_by_environment() {
    const char* value = std::getenv("UEVR_FAW_NO_UI_HOOK");
    return value != nullptr && value[0] != '\0' && value[0] != '0';
}

namespace detail {

inline bool matches(std::span<const uint8_t> code, size_t offset,
                    std::span<const uint8_t> pattern, std::span<const uint8_t> mask) {
    if (offset > code.size() || code.size() - offset < pattern.size()) { return false; }
    for (size_t i = 0; i < pattern.size(); ++i) {
        if ((code[offset + i] & mask[i]) != (pattern[i] & mask[i])) { return false; }
    }
    return true;
}

inline int32_t read_i32(std::span<const uint8_t> code, size_t offset) {
    int32_t value{};
    std::memcpy(&value, code.data() + offset, sizeof(value));
    return value;
}

inline uintptr_t rel32_target(uintptr_t address, size_t instruction_offset, size_t instruction_length,
                              std::span<const uint8_t> code, size_t disp_offset) {
    const int64_t disp = read_i32(code, disp_offset);
    const auto next = static_cast<int64_t>(address + instruction_offset + instruction_length);
    const auto target = next + disp;
    return target > 0 ? static_cast<uintptr_t>(target) : 0;
}

} // namespace detail

inline bool destroy_matches(const from_another_world::Memory& memory, uintptr_t destroy) {
    std::array<uint8_t, destroy_fingerprint.size()> bytes{};
    return destroy != 0 && memory.read != nullptr &&
        memory.read(memory.context, destroy, bytes.data(), bytes.size()) && bytes == destroy_fingerprint;
}

inline bool release_helper_matches(const from_another_world::Memory& memory, uintptr_t helper) {
    std::array<uint8_t, release_helper_prefix.size()> prefix{};
    std::array<uint8_t, release_helper_mask.size()> mask{};
    return helper != 0 && memory.read != nullptr &&
        memory.read(memory.context, helper, prefix.data(), prefix.size()) && prefix == release_helper_prefix &&
        memory.read(memory.context, helper + release_helper_mask_offset, mask.data(), mask.size()) &&
        mask == release_helper_mask;
}

// \`code\` is the module window that starts at \`address\`, immediately after the first
// scope-constructor call that UEVR's analysis rejected.
inline std::optional<Proof> find_allocator(std::span<const uint8_t> code, uintptr_t address,
                                           const from_another_world::Memory& memory) {
    using detail::matches;

    constexpr size_t allocator_length = 58;   // lea r9 .. mov rax,[rbp+OUT]
    constexpr size_t release_window = 0x120;  // bytes after the allocator to search for the release shape

    constexpr std::array<uint8_t, 4> lea_r9{0x4c,0x8d,0x4d,0x00};
    constexpr std::array<uint8_t, 4> lea_r9_mask{0xff,0xff,0xff,0x00};
    constexpr std::array<uint8_t, 3> mov_rcx_rip{0x48,0x8b,0x0d};
    constexpr std::array<uint8_t, 3> lea_r8_rip{0x4c,0x8d,0x05};
    constexpr std::array<uint8_t, 3> lea_rdx_rbp{0x48,0x8d,0x55};
    constexpr std::array<uint8_t, 3> mov_rax_rcx{0x48,0x8b,0x01};
    constexpr std::array<uint8_t, 2> call_rax_disp32{0xff,0x90};
    constexpr std::array<uint8_t, 3> lea_rcx_rbp{0x48,0x8d,0x4d};
    constexpr std::array<uint8_t, 4> mov_rbx_rsp{0x48,0x8b,0x5c,0x24};
    constexpr std::array<uint8_t, 3> mov_rax_rbp{0x48,0x8b,0x45};

    auto eq = [&](size_t offset, const auto& pattern) {
        return offset <= code.size() && code.size() - offset >= pattern.size() &&
            std::memcmp(code.data() + offset, pattern.data(), pattern.size()) == 0;
    };

    std::optional<Proof> result;

    for (size_t p = 0; p + allocator_length <= code.size(); ++p) {
        if (!matches(code, p, lea_r9, lea_r9_mask) ||
            !eq(p + 4, mov_rcx_rip) || !eq(p + 11, lea_r8_rip) || !eq(p + 18, lea_rdx_rbp) ||
            !eq(p + 22, mov_rax_rcx) || !eq(p + 25, call_rax_disp32)) { continue; }

        // call [rax+disp32]: a plausible vtable slot, high half of the displacement clear.
        const auto vtable_offset = static_cast<uint32_t>(detail::read_i32(code, p + 27));
        if (vtable_offset < 0x40 || vtable_offset >= 0x1000 || vtable_offset % sizeof(uintptr_t) != 0) { continue; }

        const auto output_disp = static_cast<int8_t>(code[p + 21]);

        // Two scope destructors: lea rcx,[rbp+X] ; call rel32
        if (!eq(p + 31, lea_rcx_rbp) || code[p + 35] != 0xe8 ||
            !eq(p + 40, lea_rcx_rbp) || code[p + 44] != 0xe8 ||
            !eq(p + 49, mov_rbx_rsp) ||
            !eq(p + 54, mov_rax_rbp) || static_cast<int8_t>(code[p + 57]) != output_disp) { continue; }

        const auto dtor1 = detail::rel32_target(address, p + 35, 5, code, p + 36);
        const auto dtor2 = detail::rel32_target(address, p + 44, 5, code, p + 45);
        if (dtor1 == 0 || dtor2 == 0 || dtor1 == dtor2) { continue; }

        // Receiver (GDynamicRHI) and immediate command list globals, both RIP-relative.
        const auto receiver = detail::rel32_target(address, p + 4, 7, code, p + 7);
        const auto commands = detail::rel32_target(address, p + 11, 7, code, p + 14);
        if (receiver == 0 || commands == 0 || receiver == commands) { continue; }

        // Release of the previous ref, shortly after:
        //   48 8d 4b 08 | ba 03 00 00 00 | e8 <helper> | 85 c0 | 79 ??
        //   ...        75 08 | 48 8b cb | e8 <destroy>
        uintptr_t helper{}, destroy{};
        const auto begin = p + allocator_length;
        const auto end = std::min(code.size(), begin + release_window);
        for (size_t q = begin; q + 16 <= end; ++q) {
            if (code[q] == 0x48 && code[q + 1] == 0x8d && code[q + 2] == 0x4b && code[q + 3] == 0x08 &&
                code[q + 4] == 0xba && detail::read_i32(code, q + 5) == 3 && code[q + 9] == 0xe8 &&
                code[q + 14] == 0x85 && code[q + 15] == 0xc0) {
                helper = detail::rel32_target(address, q + 9, 5, code, q + 10);
                break;
            }
        }
        for (size_t q = begin; q + 10 <= end; ++q) {
            if (code[q] == 0x75 && code[q + 1] == 0x08 && code[q + 2] == 0x48 && code[q + 3] == 0x8b &&
                code[q + 4] == 0xcb && code[q + 5] == 0xe8) {
                destroy = detail::rel32_target(address, q + 5, 5, code, q + 6);
                break;
            }
        }

        if (!release_helper_matches(memory, helper) || !destroy_matches(memory, destroy)) { continue; }
        if (result) { return std::nullopt; }   // ambiguous: refuse

        Proof proof{};
        proof.callsite = address + p + 25;
        proof.receiver_cell = receiver;
        proof.command_list = commands;
        proof.output_displacement = output_disp;
        proof.vtable_offset = vtable_offset;
        proof.length = 6;
        std::memcpy(proof.bytes.data(), code.data() + p + 25, proof.length);
        proof.release_helper = helper;
        proof.destroy = destroy;
        result = proof;
    }

    return result;
}

} // namespace uevr::from_another_world_ui
