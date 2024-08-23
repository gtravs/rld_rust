// macros.rs

/// 获取函数指针的宏
#[macro_export]
macro_rules! get_function {
    ($module_base:expr, $hash:expr, $fn_type:ty) => {{
        let func_addr = get_export_by_hash($module_base, $hash).unwrap();
        let func: $fn_type = core::mem::transmute(func_addr);
        func
    }};
}

/// 设置节的内存保护属性的宏
#[macro_export]
macro_rules! set_section_protection {
    ($section:expr, $new_module_base:expr, $VirtualProtect:expr) => {{
        let mut protection = 0;
        let mut old_protection = 0;

        if $section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            if $section.Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                protection = if $section.Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_WRITECOPY
                };
            } else if $section.Characteristics & IMAGE_SCN_MEM_READ != 0 {
                protection = PAGE_EXECUTE_READ;
            } else {
                protection = PAGE_EXECUTE;
            }
        } else if $section.Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            protection = if $section.Characteristics & IMAGE_SCN_MEM_READ != 0 {
                PAGE_READWRITE
            } else {
                PAGE_WRITECOPY
            };
        } else if $section.Characteristics & IMAGE_SCN_MEM_READ != 0 {
            protection = PAGE_READONLY;
        }

        let destination = $new_module_base.cast::<u8>().add($section.VirtualAddress as usize);
        let size = $section.SizeOfRawData as usize;

        $VirtualProtect(destination as _, size, protection, &mut old_protection);
    }};
}

/// 处理重新定位的宏
#[macro_export]
macro_rules! apply_relocations {
    ($base_relocation:expr, $base_relocation_end:expr, $new_module_base:expr, $delta:expr) => {{
        while (*$base_relocation).VirtualAddress != 0u32 && (*$base_relocation).VirtualAddress as usize <= $base_relocation_end && (*$base_relocation).SizeOfBlock != 0u32 {
            let address = ($new_module_base as usize + (*$base_relocation).VirtualAddress as usize) as isize;
            let item = ($base_relocation as usize + core::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
            let count = ((*$base_relocation).SizeOfBlock as usize - core::mem::size_of::<IMAGE_BASE_RELOCATION>()) / core::mem::size_of::<u16>() as usize;

            for i in 0..count {
                let type_field = (item.offset(i as isize).read() >> 12) as u32;
                let offset = item.offset(i as isize).read() & 0xFFF;

                if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                    *((address + offset as isize) as *mut isize) += $delta;
                }
            }

            $base_relocation = ($base_relocation as usize + (*$base_relocation).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
        }
    }}
}

/// 复制节的宏
#[macro_export]
macro_rules! copy_sections {
    ($nt_headers:expr, $module_base:expr, $new_module_base:expr) => {{
        let section_header = (&(*$nt_headers).OptionalHeader as *const _ as usize + (*$nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;
        for i in 0..(*$nt_headers).FileHeader.NumberOfSections {
            let section_header_i = &*(section_header.add(i as usize));
            let destination = $new_module_base.cast::<u8>().add(section_header_i.VirtualAddress as usize);
            let source = ($module_base as usize + section_header_i.PointerToRawData as usize) as *const u8;
            let size = section_header_i.SizeOfRawData as usize;

            let source_data = core::slice::from_raw_parts(source as *const u8, size);
            for x in 0..size {
                let src_data = source_data[x];
                let dest_data = destination.add(x);
                *dest_data = src_data;
            }
        }
        for i in 0..(*$nt_headers).OptionalHeader.SizeOfHeaders {
        $new_module_base.cast::<u8>().add(i as usize).write($module_base.add(i as usize).read());
        }
    }};
}

/// 处理导入表的宏
#[macro_export]
macro_rules! handle_imports {
    ($import_directory:expr, $new_module_base:expr, $LoadLibraryA:expr, $GetProcAddress:expr) => {{
        while (*$import_directory).Name != 0x0 {
            let dll_name = ($new_module_base as usize + (*$import_directory).Name as usize) as *const i8;

            if dll_name.is_null() {
                return;
            }

            let dll_handle = $LoadLibraryA(dll_name as _);

            if dll_handle == null_mut() {
                return;
            }

            let mut original_thunk = if ($new_module_base as usize + (*$import_directory).Anonymous.OriginalFirstThunk as usize) != 0 {
                let orig_thunk = ($new_module_base as usize + (*$import_directory).Anonymous.OriginalFirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
                orig_thunk
            } else {
                let thunk = ($new_module_base as usize + (*$import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
                thunk
            };

            let mut thunk = ($new_module_base as usize + (*$import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

            while (*original_thunk).u1.Function != 0 {
                let snap_result = ((*original_thunk).u1.Ordinal) & IMAGE_ORDINAL_FLAG64 != 0;

                if snap_result {
                    let fn_ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as *const u8;
                    (*thunk).u1.Function = $GetProcAddress(dll_handle, fn_ordinal).unwrap() as _;
                } else {
                    let thunk_data = ($new_module_base as usize + (*original_thunk).u1.AddressOfData as usize) as *mut IMAGE_IMPORT_BY_NAME;
                    let fn_name = (*thunk_data).Name.as_ptr();
                    (*thunk).u1.Function = $GetProcAddress(dll_handle, fn_name as PCSTR).unwrap() as _;
                }

                thunk = thunk.add(1);
                original_thunk = original_thunk.add(1);
            }

            $import_directory = ($import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
        }
    }};
}