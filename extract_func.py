# -*- coding: utf-8 -*-
"""extract_func, get function binary code.

Copyright (c) 2022 NKAMG <zwang@nankai.edu.cn>
"""
__author__ = "NKAMG"
__version__ = "2022.4.12"
__contact__ = "zwang@nankai.edu.cn"

import idc

def extract_func(ea, file_path="func.bin"):
    list_byte = []
    func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_start == BADADDR:
        return -1
    print(hex(func_start))
    func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    if func_end == BADADDR:
        return -1
    print(hex(func_end))
    n = func_end - func_start
    print(n)
    list_byte = idc.get_bytes(func_start, n)
    print(hex(list_byte[0]))
    #print(hex(list_byte[1]))
    #print(hex(list_byte[2]))
    with open(file_path, "wb") as f:
        f.write(list_byte)

if __name__ == '__main__':
    """TODO： 添加三个参数：目标程序、目标序的函数地址、保存的文件名 """
    ea = 0x40112d
    extract_func(ea, "func.bin")