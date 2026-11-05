#pragma once

// From Another World (UE 5.6.1-44394996, D3D12) FRHITexture -> ID3D12Resource layout.
//
// Derived from the shipping binary, not from the engine source:
//   * The FRHITexture vtable used by the Slate viewport target lives at exe+0xF99E7C8.
//   * vtable slot 5 is `xor eax,eax; ret` (null stub, NOT GetNativeResource).
//   * vtable slot 7 (exe+0x5FE0E70) is the real accessor. Its fast path is
//         native = [[this + 0x178] + 0x20]
//     and it only falls back to a virtual call (vtable slot 9) when the first
//     hop is null.
//
// Everything here only READS memory. No game code is ever executed, which is the
// property UEVR's generic UE5.6 path needs ("Refusing unsafe probing").
// The header has no Windows dependency so the logic can be unit-tested anywhere.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <string_view>

namespace uevr::from_another_world {

inline constexpr uint32_t native_getter_vtable_slot = 7;
inline constexpr uint32_t first_hop_offset = 0x178;
inline constexpr uint32_t second_hop_offset = 0x20;

// Exact bytes of FUN_145fe0e70 (71 bytes). Matching them proves that slot 7 of the
// vtable is the accessor we decoded, and therefore that the two offsets apply.
inline constexpr std::array<uint8_t, 71> native_getter_code{
    0x40, 0x53,                                     // push rbx
    0x48, 0x83, 0xEC, 0x20,                         // sub  rsp,0x20
    0x48, 0x8B, 0x81, 0x78, 0x01, 0x00, 0x00,       // mov  rax,[rcx+0x178]
    0x33, 0xDB,                                     // xor  ebx,ebx
    0x48, 0x85, 0xC0,                               // test rax,rax
    0x74, 0x09,                                     // je   +9
    0x48, 0x8B, 0x58, 0x20,                         // mov  rbx,[rax+0x20]
    0x48, 0x85, 0xDB,                               // test rbx,rbx
    0x75, 0x21,                                     // jne  done
    0x48, 0x8B, 0x01,                               // mov  rax,[rcx]
    0xFF, 0x50, 0x48,                               // call [rax+0x48]
    0x48, 0x85, 0xC0,                               // test rax,rax
    0x74, 0x16,                                     // je   done
    0x48, 0x8B, 0x80, 0x78, 0x01, 0x00, 0x00,       // mov  rax,[rax+0x178]
    0x48, 0x85, 0xC0,                               // test rax,rax
    0x74, 0x0A,                                     // je   done
    0x48, 0x8B, 0x40, 0x20,                         // mov  rax,[rax+0x20]
    0x48, 0x83, 0xC4, 0x20,                         // add  rsp,0x20
    0x5B,                                           // pop  rbx
    0xC3,                                           // ret
    0x48, 0x8B, 0xC3,                               // done: mov rax,rbx
    0x48, 0x83, 0xC4, 0x20,                         // add  rsp,0x20
    0x5B,                                           // pop  rbx
    0xC3};                                          // ret

// Read callback: copy `size` bytes from `address` into `out`; return false if the
// range is not readable. Implemented with ReadProcessMemory in the game build.
struct Memory {
    void* context{};
    bool (*read)(void* context, uintptr_t address, void* out, size_t size){};

    template <typename T>
    bool read_value(uintptr_t address, T& out) const {
        return read != nullptr && address != 0 && read(context, address, &out, sizeof(T));
    }
};

// True when `executable_path` names From Another World's executable.
inline bool is_executable_path(std::wstring_view executable_path) {
    const auto slash = executable_path.find_last_of(L"\\/");
    const auto name = slash == std::wstring_view::npos ? executable_path : executable_path.substr(slash + 1);

    constexpr std::wstring_view expected = L"fromanotherworld.exe";
    if (name.size() != expected.size()) {
        return false;
    }

    for (size_t i = 0; i < name.size(); ++i) {
        if (static_cast<wchar_t>(std::towlower(static_cast<wint_t>(name[i]))) != expected[i]) {
            return false;
        }
    }

    return true;
}

// True when `vtable` slot 7 points at code that is byte-identical to the accessor
// we decoded. This doubles as the build fingerprint.
inline bool getter_matches(const Memory& memory, uintptr_t vtable) {
    uintptr_t getter{};
    if (!memory.read_value(vtable + native_getter_vtable_slot * sizeof(uintptr_t), getter) || getter == 0) {
        return false;
    }

    std::array<uint8_t, native_getter_code.size()> code{};
    if (memory.read == nullptr || !memory.read(memory.context, getter, code.data(), code.size())) {
        return false;
    }

    return code == native_getter_code;
}

// Resolves [[texture + 0x178] + 0x20] without executing any game code.
// Returns 0 whenever anything is unexpected (unknown build, null hop, unreadable
// memory). The caller must still validate the result as a real ID3D12Resource.
inline uintptr_t native_resource_address(const Memory& memory, uintptr_t texture) {
    if (texture == 0) {
        return 0;
    }

    uintptr_t vtable{};
    if (!memory.read_value(texture, vtable) || vtable == 0 || !getter_matches(memory, vtable)) {
        return 0;
    }

    uintptr_t first{};
    if (!memory.read_value(texture + first_hop_offset, first) || first == 0) {
        // The game's own accessor would call a virtual here. Fail closed instead.
        return 0;
    }

    uintptr_t native{};
    if (!memory.read_value(first + second_hop_offset, native)) {
        return 0;
    }

    return native;
}

} // namespace uevr::from_another_world
