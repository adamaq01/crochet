# Crochet

This crate is a simple runtime hooking library based on [detour](https://github.com/lostinspiration/detour-rs) and
heavily inspired by [skyline-rs](https://github.com/ultimate-research/skyline-rs) (by heavily inspired I mean "I copied a lot from their awesome project so go check it out").

## Installation

```toml
[dependencies]
crochet = "0.1"
```

## Usage

```rust
use winapi::ctypes::c_int;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, UINT};
use winapi::shared::windef::HWND;
use winapi::um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, LPCWSTR};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: DWORD,
    reserved: LPVOID,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => crochet::enable!(messageboxw_hook).expect("Could not enable messageboxw hook"),
        DLL_PROCESS_DETACH => crochet::disable!(messageboxw_hook).expect("Could not disable messageboxw hook"),
        _ => {}
    }

    TRUE
}

#[crochet::hook("user32.dll", "MessageBoxW")]
fn messageboxw_hook(hwnd: HWND, _text: LPCWSTR, caption: LPCWSTR, u_type: UINT) -> c_int {
    let text = "Tu as fait mouche, Mouche !\0".encode_utf16().collect::<Vec<u16>>();

    call_original!(hwnd, text.as_ptr(), caption, u_type)
}
```

## License

MIT
