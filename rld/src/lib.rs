#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

mod pe;
mod macros;

use core::{ffi::c_void, ptr::null_mut, slice::from_raw_parts, mem::{transmute, size_of}, arch::asm};
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, FARPROC, HANDLE, UNICODE_STRING, HMODULE, BOOLEAN},
        System::{
            Diagnostics::{Debug::{
                IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            }},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VIRTUAL_ALLOCATION_TYPE,
                VIRTUAL_FREE_TYPE,
            },
            SystemServices::{
                DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER,IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64, IMAGE_IMPORT_BY_NAME,
            },
            WindowsProgramming::{IMAGE_THUNK_DATA64},
        },
    },
};
use windows_sys::Win32::Foundation::NTSTATUS;
use crate::pe::{get_export_by_hash, get_loaded_module_hash};
pub type SIZE_T = usize;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// 使用 no_std 需要 _DllMainCRTStartup 和 _fltused，而不仅仅是 DllMain
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn _DllMainCRTStartup(
    _module: HMODULE,
    _call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    1
}

/// 反射式 DLL
#[link_section = ".text$A"]
#[no_mangle]
pub unsafe extern "system" fn rld(payload: *mut c_void, function_hash: u32, user_data: *mut c_void, user_data_len: u32, _shellcode_bin: *mut c_void, _flags: u32)
{
    let module_base = payload as *mut u8;
    if module_base.is_null() {
        return;
    }
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    let nt_headers  = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    // 哈希值
    let KERNEL32_HASH = 0x6DDB9555;
    let NTDLL_HASH = 0x1EDAB0ED;
    let NT_ALLOCATE_VIRTUAL_MEMORY_HASH =  0xF783B8EC;
    let LOAD_LIBRARY_A_HASH: u32 = 0xB7072FDB;
    let GET_PROC_ADDRESS_HASH: u32 = 0xDECFC1BF;
    let VIRTUAL_PROTECT_HASH: u32 = 0xe857500d;
    let FLUSH_INSTRUCTION_CACHE_HASH: u32 = 0xefb7bf9d;
    let VIRTUAL_FREE_HASH: u32 = 0xe144a60e;
    let EXIT_THREAD_HASH: u32 = 0xc165d757;
    let VIRTUAL_ALLOC_HASH: u32 = 0x97bc257;

    let kernel32_base = get_loaded_module_hash(KERNEL32_HASH).unwrap();
    let ntdll_base = get_loaded_module_hash(NTDLL_HASH).unwrap();
    if kernel32_base.is_null() || ntdll_base.is_null() {
        return;
    }

    // get func ptr
    #[allow(non_camel_case_types)]
    type fnLoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

    #[allow(non_camel_case_types)]
    type fnGetProcAddress = unsafe extern "system" fn(HMODULE: HMODULE, lpprocname: PCSTR) -> FARPROC;

    #[allow(non_camel_case_types)]
    type FnNtAllocateVirtualMemory = unsafe extern "system" fn(ProcessHandle: HANDLE, BaseAddress: *mut *mut core::ffi::c_void, ZeroBits: usize, RegionSize: *mut SIZE_T, AllocationType: u32, Protect: u32) -> NTSTATUS;

    #[allow(non_camel_case_types)]
    type fnFlushInstructionCache = unsafe extern "system" fn(hprocess: HANDLE, lpbaseaddress: *const c_void, dwsize: usize) -> BOOL;

    #[allow(non_camel_case_types)]
    type fnVirtualProtect = unsafe extern "system" fn(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL;

    #[allow(non_camel_case_types)]
    type fnVirtualFree = unsafe extern "system" fn(lpaddress: *mut c_void, dwsize: usize, dwfreetype: VIRTUAL_FREE_TYPE) -> BOOL;
    #[allow(non_camel_case_types)]
    type fnVirtualAlloc = unsafe extern "system" fn(lpaddress: *const c_void, dwsize: usize, flallocationtype: VIRTUAL_ALLOCATION_TYPE, flprotect: PAGE_PROTECTION_FLAGS) -> *mut c_void;

    #[allow(non_camel_case_types)]
    type fnExitThread = unsafe extern "system" fn(dwexitcode: u32) -> !;

    // 使用宏来获取函数地址
    let LoadLibraryA = get_function!(kernel32_base, LOAD_LIBRARY_A_HASH, fnLoadLibraryA);
    let GetProcAddress = get_function!(kernel32_base, GET_PROC_ADDRESS_HASH, fnGetProcAddress);
    let NtAllocateVirtualMemory = get_function!(ntdll_base, NT_ALLOCATE_VIRTUAL_MEMORY_HASH, FnNtAllocateVirtualMemory);
    let VirtualProtect = get_function!(kernel32_base, VIRTUAL_PROTECT_HASH, fnVirtualProtect);
    let FlushInstructionCache = get_function!(kernel32_base, FLUSH_INSTRUCTION_CACHE_HASH, fnFlushInstructionCache);
    let _VirtualFree = get_function!(kernel32_base, VIRTUAL_FREE_HASH, fnVirtualFree);
    let _ExitThread = get_function!(kernel32_base, EXIT_THREAD_HASH, fnExitThread);
    let _VirtualAlloc = get_function!(kernel32_base, VIRTUAL_ALLOC_HASH, fnVirtualAlloc);

    let mut image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let mut new_module_base = (*nt_headers).OptionalHeader.ImageBase as *mut c_void;
    if NtAllocateVirtualMemory(-1isize as HANDLE, &mut new_module_base, 0, &mut image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0 {
        let mut new_module_address = null_mut();
        NtAllocateVirtualMemory(-1isize as HANDLE, &mut new_module_address, 0, &mut image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    // 复制节
    copy_sections!(nt_headers, module_base, new_module_base);

    let delta = new_module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;
    let mut base_relocation = (new_module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;
    if base_relocation.is_null() {
        return;
    }
    let base_relocation_end = base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;
    apply_relocations!(base_relocation, base_relocation_end, new_module_base, delta);
    let mut import_directory = (new_module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;
    if import_directory.is_null() {
        return;
    }
    // 处理导入表
    handle_imports!(import_directory, new_module_base, LoadLibraryA, GetProcAddress);
    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;
    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section_header_i = &*(section_header.add(i as usize));
        set_section_protection!(section_header_i, new_module_base,VirtualProtect);
    }
    // 刷新指令缓存以避免使用旧代码
    FlushInstructionCache(-1 as _, null_mut(), 0);
    let entry_point = new_module_base as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize;
    #[allow(non_camel_case_types)]
    type fnDllMain = unsafe extern "system" fn(module: HMODULE, call_reason: u32, reserved: *mut c_void) -> BOOL;
    #[allow(non_snake_case)]
    let DllMain = transmute::<_, fnDllMain>(entry_point);
    if _flags == 0 {
        DllMain(new_module_base as _, DLL_PROCESS_ATTACH, module_base as _);
    } else {
        #[allow(non_camel_case_types)]
        type fnUserFunction = unsafe extern "system" fn(user_data: *mut c_void, user_data_length: u32) -> BOOL;
        let user_function_address = get_export_by_hash(new_module_base as _, function_hash).unwrap();
        let UserFunction = transmute::<_, fnUserFunction>(user_function_address);
        UserFunction(user_data, user_data_len);
    }
}
