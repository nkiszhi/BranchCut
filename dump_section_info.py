# -*- coding: utf-8 -*-
"""dump_function_info, 提取PE文件节的信息

Copyright (c) 2022 NKAMG <zwang@nankai.edu.cn>
"""

__author__ = "NKAMG"
__version__ = "2022.4.12"
__contact__ = "zwang@nankai.edu.cn"

import idautils
import idc
import ida_segment


# 提取PE文件中节的信息
def dump_section_info():
  # 输出节的内存访问权限全局变量的定义值
  print(" ida_segment.SEGPERM_EXEC = %d" % ida_segment.SEGPERM_EXEC)
  print(" ida_segment.SEGPERM_WRITE = %d" % ida_segment.SEGPERM_WRITE)
  print(" ida_segment.SEGPERM_READ = %d" % ida_segment.SEGPERM_READ)

  # 输出节的类型全局变量的定义值
  print(" ida_segment.SEG_CODE = %d" % ida_segment.SEG_CODE)
  print(" ida_segment.SEG_DATA = %d" % ida_segment.SEG_DATA)
  print(" ida_segment.SEG_BSS = %d" % ida_segment.SEG_BSS)
  print(" ida_segment.SEG_NULL = %d" % ida_segment.SEG_NULL)

  # 输出第一个节的内存起始地址
  print(" The first segment start address: 0x%x" % idc.get_first_seg())

  for s in idautils.Segments():    
    print("%s" % idc.get_segm_name(s))
    print(" - start address: 0x%x" % idc.get_segm_start(s))
    print(" - end address: 0X%x" % idc.get_segm_end(s))
    segm_p = idc.get_segm_attr(s, idc.SEGATTR_PERM) #获取节的内存访问权限
    if(segm_p & ida_segment.SEGPERM_EXEC):  # 判断节是否具有可执行的内存访问权限
      print("Executable")
    if(segm_p & ida_segment.SEGPERM_WRITE): # 判断节是否具有可写的内存访问权限
      print("Writeable")
    if(segm_p & ida_segment.SEGPERM_READ) : # 判断节是否具有可读的内存访问权限
      print("Readable")

    segm_type = idc.get_segm_attr(s, idc.SEGATTR_TYPE) # 获取节的类型
    if(segm_type == ida_segment.SEG_CODE):
      print("code segment")
    if(segm_type == ida_segment.SEG_DATA):
      print("data segment")
    if(segm_type == ida_segment.SEG_BSS) :
      print("bss segment")
    if(segm_type == ida_segment.SEG_NULL) :
      print("empty segment")

def main():
  dump_section_info()

if __name__ == "__main__":
  main()