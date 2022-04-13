# -*- coding: utf-8 -*-
"""dump_function_info, 提取PE文件中的函数信息

Copyright (c) 2022 NKAMG <zwang@nankai.edu.cn>
"""
__author__ = "NKAMG"
__version__ = "2022.4.13"
__contact__ = "zwang@nankai.edu.cn"

import idc
import lief
import pefile

def extract_func(ea, file_path="func.bin"):
    list_byte = []
    func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_start == BADADDR:
        return False
    #print(hex(func_start))
    func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    if func_end == BADADDR:
        return False
    #print(hex(func_end))
    n = func_end - func_start
    #print(n)
    list_byte = idc.get_bytes(func_start, n)
    #print(hex(list_byte[0]))
    #print(hex(list_byte[1]))
    #print(hex(list_byte[2]))
    return list_byte

def insert_func(pe_file, list_byte):
    binary = lief.parse(pe_file)
    pe = pefile.PE(pe_file)
    new_section = lief.PE.Section(".new") # new section name
    va = pe.sections[-1].VirtualAddress
    #print(hex(va))
    size = pe.sections[-1].Misc_VirtualSize
    #print(hex(size))
    new_va = va + size
    new_section.virtual_address = int(new_va/0x1000+1)*0x1000
    #print(hex(new_va))
    #print(hex(new_section.virtual_address))
    new_section.virtual_size = len(list_byte)
    #print(hex(new_section.virtual_size))
    new_section.characteristics = 0x60000020
    #print(hex(new_section.characteristics))
    offset = pe.sections[-1].PointerToRawData
    #print(hex(offset))
    size = pe.sections[-1].SizeOfRawData
    #print(hex(size))
    new_offset = offset + size
    #print(hex(new_offset))
    new_section.pointerto_raw_data = int(new_offset/0x200+1)*0x200
    #print(hex(new_section.pointerto_raw_data))
    new_section.sizeof_raw_data = len(list_byte)
    #print(" ".join("0x{:02X}".format(x) for x in list_byte))
    new_section.content = [int(x) for x in list_byte] 
    #print(hex(new_section.sizeof_raw_data))
    binary.optional_header.dll_characteristics =  binary.optional_header.dll_characteristics & 0xffbf 
    binary.add_section(new_section)
    binary.write(pe_file + ".crafted")

if __name__ == '__main__':
    """TODO： 添加三个参数：源程序、源程序的函数地址、目的程序 """
    ea = 0x40112d
    list_byte = extract_func(ea, "func.bin")
    if(list_byte):
        insert_func("boat.exe", list_byte)