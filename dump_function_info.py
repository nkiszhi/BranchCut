# -*- coding: utf-8 -*-
"""dump_function_info, 提取PE文件中的函数信息

Copyright (c) 2022 NKAMG <zwang@nankai.edu.cn>
"""
__author__ = "NKAMG"
__version__ = "2022.4.12"
__contact__ = "zwang@nankai.edu.cn"

import idc
import idautils
import ida_segment
import json
import pefile

# 提取PE文件中的函数信息
def dump_imported_api():
  path = idc.get_idb_path() # 读取IDB文件的绝对路径
  path = path[:-4] # 去掉.idb后缀，获得IDA打开文件的绝对路径
  print(path)
  pe = pefile.PE(path) # 调用pefile模块，分析文件的PE文件结构

  dict_func = dict()
  # 遍历导入表的IMAGE_IMPORT_DESCRIPTOR结构
  for dll in pe.DIRECTORY_ENTRY_IMPORT: 
    #print(dll.dll.decode('utf-8'))
    dll_name = dll.dll.decode('utf-8')
    for func in dll.imports: # 遍历一个动态链接库所导入的所有函数
      if func.name:
        dict_func[func.name.decode('utf-8')] = dll_name # 保存函数名和函数所在的动态链接库
  #print(dict_func)
  return dict_func

def print_all_func_flag_value():
  print("FUNC_NORET：%d" % FUNC_NORET)
  print("FUNC_FAR：%d" % FUNC_FAR)
  print("FUNC_LIB：%d" % FUNC_LIB)
  print("FUNC_STATIC：%d" % FUNC_STATIC)
  print("FUNC_FRAME：%d" % FUNC_FRAME)
  print("FUNC_USERFAR：%d" % FUNC_USERFAR)
  print("FUNC_HIDDEN：%d" % FUNC_HIDDEN)
  print("FUNC_THUNK：%d" % FUNC_THUNK)
  print("FUNC_BOTTOMBP：%d" % FUNC_BOTTOMBP)
  print("FUNC_NORET_PENDING：%d" % FUNC_NORET_PENDING)
  print("FUNC_SP_READY：%d" % FUNC_SP_READY)
  print("FUNC_PURGED_OK：%d" % FUNC_PURGED_OK) 
  print("FUNC_TAIL：%d" % FUNC_TAIL)

def print_func_flags(flags):
  list_flag = []
  if(flags & FUNC_NORET):
    #print("FUNC_NORET" )
    list_flag.append("FUNC_NORET")
  if(flags & FUNC_FAR):
    #print("FUNC_FAR")
    list_flag.append("FUNC_FAR")
  if(flags & FUNC_LIB):
    #print("FUNC_LIB")
    list_flag.append("FUNC_LIB")
  if(flags & FUNC_STATIC):
    #print("FUNC_STATIC")
    list_flag.append("FUNC_STATIC")
  if(flags & FUNC_FRAME):
    #print("FUNC_FRAME")
    list_flag.append("FUNC_FRAME")
  if(flags & FUNC_USERFAR):
    #print("FUNC_USERFAR")
    list_flag.append("FUNC_USERFAR")
  if(flags & FUNC_HIDDEN):
    #print("FUNC_HIDDEN")
    list_flag.append("FUNC_HIDDEN")
  if(flags & FUNC_THUNK):
    #print("FUNC_THUNK")
    list_flag.append("FUNC_THUNK")
  if(flags & FUNC_BOTTOMBP):
    #print("FUNC_BOTTOMBP")
    list_flag.append("FUNC_BOTTOMBP")
  if(flags & FUNC_NORET_PENDING):
    #print("FUNC_NORET_PENDING")
    list_flag.append("FUNC_NORET_PENDING")
  if(flags & FUNC_SP_READY):
    #print("FUNC_SP_READY")
    list_flag.append("FUNC_SP_READY")
  if(flags & FUNC_PURGED_OK):
    #print("FUNC_PURGED_OK") 
    list_flag.append("FUNC_PURGED_OK")
  if(flags & FUNC_TAIL):
    #print("FUNC_TAIL")
    list_flag.append("FUNC_TAIL")
  return list_flag


def dump_func_info(dict_api):
  list_api = [] # 存储函数中的API调用序列
  list_flag = [] # 存储函数的类型标签
  dict_func = {}
  for s in idautils.Segments(): #遍历节表   
    segm_p = idc.get_segm_attr(s, idc.SEGATTR_PERM) # 获取节的内存访问权限
    if not (segm_p & ida_segment.SEGPERM_EXEC):  # 判断节是否具有可执行的内存访问权限
      #print("%s is not executable" %  idc.get_segm_name(s))
      continue
    print("%s" % idc.get_segm_name(s))
    print(" - start address: 0x%x" % idc.get_segm_start(s))
    print(" - end address: 0X%x" % idc.get_segm_end(s))
    segm_start = idc.get_segm_start(s)
    segm_end = idc.get_segm_end(s)
    for func_start in idautils.Functions(segm_start, segm_end): # 遍历节中的函数
      list_flag = []
      list_api = []
      func_flag = idc.get_func_attr(func_start, FUNCATTR_FLAGS) # 读取函数类型标签
      #print_func_flags(func_flags)
      if(func_flag & FUNC_LIB) or (func_flag & FUNC_THUNK):
        continue
      #print("FUNC_SP_READY")
      func_name = idc.get_func_name(func_start) # 读取函数名
      #if(func_name == "__alloca_probe"): ## ?? __alloca_probe到底是什么函数？有3个属性标签：FUNC_HIDDEN、FUNC_SP_READY、FUNC_PURGED_OK
      list_flag = print_func_flags(func_flag)
      func_end =  idc.find_func_end(func_start) # 获得函数的内存结束地址
      #print("%s: 0x%x, 0x%x" % (func_name, func_start, func_end)) 
      
      list_inst = list(idautils.FuncItems(func_start)) # 反汇编，获得函数内部指令序列
      
      for inst_ea in list_inst:
        mnem = idc.print_insn_mnem(inst_ea)
        #print(mnem)
        if mnem !='call': # 只分析call指令
          continue
        #inst = idc.generate_disasm_line(inst_ea, 0)
        #print(inst) 
        inst_op = idc.print_operand(inst_ea, 0)
        #print(inst_op)
        inst_op = inst_op.lstrip("cs:")
        inst_op = inst_op.lstrip("ds:")
        api_name = inst_op # call指令调用的函数名
        dll_name = dict_api.get(api_name) # 通过函数名查找动态链接库的名字
        if dll_name:
          #print("{}: {}".format(dll_name, inst_op))
          list_api.append("{}:{}".format(dll_name, api_name))
      if len(list_api):
        dict_func[func_name] = [hex(func_start), hex(func_end), list_flag, list_api]
  return dict_func
           
      
def main():      
  dict_api = dump_imported_api()
  dict_func = dump_func_info(dict_api)
  #print(dict_func)
  print(json.dumps(dict_func))
  with open("result.json", "w") as f:
    f.write(json.dumps(dict_func))

if __name__ == "__main__":
  main()
  

