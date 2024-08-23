use core::arch::asm;
use core::ffi::{c_void};
use core::slice::from_raw_parts;
use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, HMODULE, UNICODE_STRING};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::SystemServices::{IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64};
use windows_sys::Win32::System::Threading::{PEB};

#[link_section = ".text$B"]
pub unsafe fn get_peb() -> *mut PEB {
    let PEB: *mut PEB;
    asm!(
    "mov {}, gs:[0x60]",
    out(reg) PEB,
    options(readonly, nostack, preserves_flags),
    );
    PEB
}
#[link_section = ".text$B"]
pub unsafe fn get_loaded_module_hash(module_hash : u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut  LDR_DATA_TABLE_ENTRY;
    while !((*module_list).DllBase.is_null())
    {
        let dll_buff_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buff_ptr as *const u8,dll_length);

        if module_hash == dbj2_hash(dll_name_slice)
        {
            return Some((*module_list).DllBase as _)
        }
        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }
    return  None
}

#[link_section = ".text$B"]
/// Get the address of an export by hash
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_name_hash: u32) -> Option<usize>
{
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts((module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _,);
    let ordinals = from_raw_parts((module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames
    {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_name_hash == dbj2_hash(name_slice)
        {
            let ordinal = ordinals[i as usize] as usize;
            return Some(module_base as usize + functions[ordinal] as usize);
        }
    }

    return None;
}

#[link_section = ".text$B"]
/// Get the length of a C String
pub unsafe fn get_cstr_len(pointer: *const char) -> usize
{
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0
    {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}
#[link_section = ".text$B"]
/// Gets a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64>
{
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE
    {
        return None;
    }

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _
    {
        return None;
    }

    return Some(nt_headers);
}


/// Hash Func
#[link_section=".text$B"]
pub fn dbj2_hash(buffer: &[u8]) -> u32
{
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;
    while iter < buffer.len()
    {
        cur = buffer[iter];

        if cur ==0
        {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8)
        {
            cur -= 0x20;
        }
        hsh = hsh.wrapping_shl(5).wrapping_add(hsh).wrapping_add(cur as u32);
        iter += 1;
    }
    return hsh;
}

#[link_section = ".text$B"]
/// Read memory from a location specified by an offset relative to the beginning of the GS segment.
pub unsafe fn __readgsqword(offset: u64) -> u64
{
    let output: u64;
    asm!("mov {}, gs:[{}]", out(reg) output, in(reg) offset);
    output
}


#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

pub type PLDR_INIT_ROUTINE = Option<unsafe extern "system" fn(DllHandle: *mut c_void, Reason: u32, Context: *mut c_void) -> BOOLEAN>;
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY
{
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: BOOLEAN,
    pub ShutdownThreadId: HANDLE,
}



