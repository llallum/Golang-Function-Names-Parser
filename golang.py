import idautils
from idaapi import *
from idc import *
import string
import sys
import ida_bytes

displace = {}
min = MinEA()
max = MaxEA()




def traverse_xrefs(func):
    function_created = 0
    
    if func is None:
        return function_created
    
    func_xrefs = idaapi.get_first_cref_to(func.startEA)
    
    while(func_xrefs != BADADDR):
        if idaapi.get_func(func_xrefs) is None:
            func_end = FindCode(func_xrefs, SEARCH_DOWN)
            if GetMnem(func_end) == "jmp":
                func_start = GetOperandValue(func_end, 0)
                func_end = NextHead(func_end)
                print "Start found", hex(func_start)
                print "End found", hex(func_end)
                if(func_start < func_xrefs):
                    print "found now"
                    if idc.MakeFunction(func_start, func_end):
                        function_created+=1
      
        func_xrefs  = idaapi.get_next_cref_to(func.startEA, func_xrefs)
    
    print "Number of functions created " , function_created
        

def create_pointer(addr, force_size =4):
    if force_size == 4:
        return Dword(addr)
    else:
        return Qword(addr)


def strip_string(str):
    STRIP_CHARS =   ['(', ')', '[', ']', '{', '}', ' ' , '"']
    REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/']
    
    str = filter(lambda x: x in string.printable, str)
    
    for c in STRIP_CHARS:
        str = str.replace(c, '')
    
    for c in REPLACE_CHARS:
        str = str.replace(c, '_')
    
    return str    

    

def renamer_init():
    renamed = 0
    
    struct = FindBinary(min, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, "FB FF FF FF 00 00 01")
    
    functions =  [x for x in Functions()] 
    
    if struct is not None:
        addr_size = struct + 7       ###size of address
        num_functions = struct+8
        
        force_size = Byte(addr_size)
    
        if(force_size == 4):
            size = create_pointer(num_functions)  #32 bit
        else:
            size = create_pointer(num_functions, force_size)  #64 bit
        
        print "address size ", hex(size)
        
        for i in range(size):
            func_addr = struct + 8 + force_size + (i* force_size *2)
            start_addr = Dword(func_addr) 
            func_name_addr = Dword(func_addr+force_size) + struct + force_size      
            func_name_addr = struct + create_pointer(func_name_addr, force_size)
            func_name = GetString(func_name_addr)
            func_len = len(func_name)
            func_name = strip_string(func_name)
            #MakeStr(func_name_addr,len(func_name))
            #print hex(func_name_addr + len(func_name))
            ida_bytes.create_strlit(func_name_addr, func_len, 0)
            print "function name address" , hex(func_name_addr)
            #Jump(func_name_addr)
            print "start address" , hex(start_addr)
            
            #if idaapi.get_func_name(start_addr) is not None:
            if start_addr not in functions:
                MakeUnkn(start_addr, 1)
                MakeCode(start_addr)
                MakeFunction(start_addr)
                functions.append(start_addr)
                MakeName(start_addr, func_name)
                renamed+=1
                #print "found"
                #break
            
            #if i ==3 :
            #    break
             #print hex(struct) , hex(addr_size) , i
            #func_name = struct+(i*size+4)
            #print hex(func_addr), hex(func_name)
            #print hex(func_addr), hex(func_name_addr), hex(func_name)
            #print hex(func_name)  
    print "renamed functions " , renamed            
            




def main():         
        
    seg = None        
        
    seg = idaapi.get_segm_by_name('.data')

    opcodes = "c7 05 03 10 00 00 00 00 00 00"

    print hex(seg.startEA), hex(seg.endEA)

    runtime_ms_end = ida_search.find_binary(seg.startEA, seg.endEA, opcodes , 0, SEARCH_DOWN)

    print hex(runtime_ms_end)
    
    runtime_ms = get_func(runtime_ms_end)

    set_name(runtime_ms.startEA, "runtime_morestack", SN_PUBLIC)

    traverse_xrefs(runtime_ms)

    renamer_init()

if __name__ == "__main__":
    main()