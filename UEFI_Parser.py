import idaapi 
import idautils
import idc

import os

print("__________________________________________________________________________")
print("The programm is working")

def get_3_bytes(x):
    n = 31
    while (n >=27):
        x = x & ~(1 << n)
        n = n - 1
    return x
#----------------------------------------------------------------------------------------------------------
def serch_file(adress_start, adress_end, path):
	adress = adress_start + 0x48
	count = 0
	while (adress <= adress_end):
		adress_struct = find_binary(adress+1, 0x3, "F8")
		adress_struct = adress_struct - 0x17
		if (get_wide_byte(adress_struct + 0x12) > 0 and get_wide_byte(adress_struct + 0x12) <= 0xD):
			if (get_3_bytes(get_wide_dword(adress_struct + 0x14)) != 0):
				if ((get_3_bytes(get_wide_dword(adress_struct + 0x14)) + adress_struct) < adress_end):
					create_struct(adress_struct, -1, get_struc_name(index_EFI_FFS_FILE_HEADER))
					count += 1
					name_dir = path + '/' + str(count - 1) + " FSS " + get_GUID(adress_struct)
					os.mkdir(name_dir)
					file = name_dir + '/' + str(count - 1) + " FSS " + get_GUID(adress_struct) + '.bin'
					memdump(adress_struct, get_3_bytes(get_wide_dword(adress_struct + 0x14)), file)
					adress = adress_struct + get_3_bytes(get_wide_dword(adress_struct + 0x14))
				else:
					adress = adress_struct + 0x18
			else:
				adress = adress_struct + 0x18
		else:
			adress = adress_struct + 0x18
#----------------------------------------------------------------------------------------------------------
def get_FVHLength(A):
	N = 0
	M = 16
	FvLength = (A >> N) & (1 << M - N + 1) - 1
	return FvLength
#-----------------------------------------------------------------------------------------------------------
def get_GUID(ea):
	GUID = ""
	dword = hex(get_wide_dword(ea))[2:-1]
	GUID += dword
	GUID += "-"
	n = 0
	while (n < 2):
		word = hex(get_wide_word(ea + 4 + (2*n) ))[2:-1]
		GUID += word
		GUID += "-"
		n += 1
	n = 0
	while (n < 8):
		byte = hex(get_wide_byte(ea + 8 + n))[2:]
		GUID += byte
		if (n < 7):
			GUID += "-"
		n += 1
	return GUID
#--------------------------------------------------------------------------------------------------------------
def memdump(ea, size, file):
    data = idc.GetManyBytes(ea, size)
    with open(file, "wb") as fp:
        fp.write(data)
#----------------------------------------------------------------------------------------------------------------------------------	
#CREATE   GUID

index_GIUD_struct = get_first_struc_idx()
add_struc(get_first_struc_idx(), "GUID", 0)
index_GIUD_struct = get_struc_id("GUID");

add_struc_member(index_GIUD_struct, "anonymous_0",	0,	    0x20000400,	-1,	4)
add_struc_member(index_GIUD_struct, "anonymous_1",	0X4,	0x10000400,	-1,	2)
add_struc_member(index_GIUD_struct, "anonymous_2",	0X6,	0x10000400,	-1,	2)
add_struc_member(index_GIUD_struct, "anonymous_3",	0X8,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_4",	0X9,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_5",	0XA,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_6",	0XB,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_7",	0XC,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_8",	0XD,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_9",	0XE,	0x000400,	-1,	1)
add_struc_member(index_GIUD_struct, "anonymous_10",	0XF,	0x000400,	-1,	1)
#----------------------------------------------------------------------------------------------------------------------------------
#CREATE  EFI_FV_BLOCK_MAP

index_EFI_FV_BLOCK_MAP = index_GIUD_struct + 1
add_struc(index_EFI_FV_BLOCK_MAP, "EFI_FV_BLOCK_MAP", 0)
index_EFI_FV_BLOCK_MAP = get_struc_id("EFI_FV_BLOCK_MAP")

add_struc_member(index_EFI_FV_BLOCK_MAP, "NumBloks",	0,	0x20000400,	-1,	4)
add_struc_member(index_EFI_FV_BLOCK_MAP, "Length",	  0X4,	0x20000400,	-1,	4)
add_struc_member(index_EFI_FV_BLOCK_MAP, "Null1",	  0X8,	0x20000400,	-1,	4)
add_struc_member(index_EFI_FV_BLOCK_MAP, "Null2",	  0XC,	0x20000400,	-1,	4)
#----------------------------------------------------------------------------------------------------------------------------------
#CREATE  EFI_FIRMWARE_VOLUME_HEADER

index_EFI_FIRMWARE_VOLUME_HEADER = index_EFI_FV_BLOCK_MAP + 1
add_struc(index_EFI_FIRMWARE_VOLUME_HEADER, "EFI_FIRMWARE_VOLUME_HEADER", 0)
index_EFI_FIRMWARE_VOLUME_HEADER = get_struc_id("EFI_FIRMWARE_VOLUME_HEADER")

add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "ZeroVector",	    0,	    0x002400,	-1,	                               16)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "FileSystemGuid",	0X10,	0x60000400,	get_struc_id("GUID"),	           16)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "FvLength",	        0X20,	0x30008400,	-1,	                                8)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "Signature",	        0X28,	0x5000c400,	 0,	                                4)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "Attributes",	    0X2C,	0x20000400,	-1,	                                4)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "HeaderLength",	    0X30,	0x10000400,	-1,	                                2)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "Checksum",	        0X32,	0x10000400,	-1,	                                2)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "ExtHeaderOffset",	0X34,	0x10000400,	-1,	                                2)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "Reserved",	        0X36,	0x000400,	-1,	                                1)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "Revision",	        0X37,	0x000400,	-1,	                                1)
add_struc_member(index_EFI_FIRMWARE_VOLUME_HEADER, "BlockMap[]",	    0X38,	0x60000400,	get_struc_id("EFI_FV_BLOCK_MAP"),  16)
#----------------------------------------------------------------------------------------------------------------------------------
#CREATE EFI_FSS_INTEGRITY_CHECK

index_EFI_FSS_INTEGRITY_CHECK = index_EFI_FIRMWARE_VOLUME_HEADER + 1
add_struc(index_EFI_FSS_INTEGRITY_CHECK, "EFI_FSS_INTEGRITY_CHECK", 0)
index_EFI_FSS_INTEGRITY_CHECK = get_struc_id("EFI_FSS_INTEGRITY_CHECK")

add_struc_member(index_EFI_FSS_INTEGRITY_CHECK, "Header",   0,	    0x000400,	-1,	1)
add_struc_member(index_EFI_FSS_INTEGRITY_CHECK, "File",	    0X1,	0x000400,	-1,	1)
#------------------------------------------------------------------------------------------------------------------------------------  
#CREATE EFI_FFS_FILE_HEADER

index_EFI_FFS_FILE_HEADER = index_EFI_FSS_INTEGRITY_CHECK + 1
add_struc(index_EFI_FFS_FILE_HEADER, "EFI_FFS_FILE_HEADER", 0)
index_EFI_FFS_FILE_HEADER = get_struc_id("EFI_FFS_FILE_HEADER")

add_struc_member(index_EFI_FFS_FILE_HEADER, "Name",	            0,	    0x60000400,	 get_struc_id("GUID"),	                   16)
add_struc_member(index_EFI_FFS_FILE_HEADER, "IntegrityCheck",	0X10,	0x60000400,	 get_struc_id("EFI_FSS_INTEGRITY_CHECK"),	2)
add_struc_member(index_EFI_FFS_FILE_HEADER, "Type",	            0X12,	0x000400,	 -1,	                                    1)
add_struc_member(index_EFI_FFS_FILE_HEADER, "Attributes",	    0X13,	0x000400,	 -1,	                                    1)
add_struc_member(index_EFI_FFS_FILE_HEADER, "Size",	            0X14,	0x000400,	 -1,	                                    3)
add_struc_member(index_EFI_FFS_FILE_HEADER, "State",	        0X17,	0x000400,	 -1,	                                    1)
#---------------------------------------------------------------------------------------------------------------------------------------
#search_FVH

VOLUME_HEADER_adr = []
next_struct = 0 
address = 0
FvLength = 0
count = 0
while (address <= get_segm_end(0)):
	next_struct = find_binary(address, 0x3, "5F 46 56 48") - 0x28
	if (next_struct < get_segm_end(0)):
		FvLength = get_wide_word(next_struct + 0x30)
		if ( FvLength == 0x48):
			create_struct(next_struct, -1, get_struc_name(index_EFI_FIRMWARE_VOLUME_HEADER))
			count += 1
			VOLUME_HEADER_adr.append(next_struct)
			name_dir = str(count - 1)+ " FVH " + get_GUID(next_struct + 0X10)
			os.mkdir(name_dir)
			address = next_struct + get_qword(next_struct + 0x20)
		else:
			address += 0x29
	else:
		break 
#----------------------------------------------------------------------------------------------------------------------------------------
#serch_files

n = 0
sum_FVH = len(VOLUME_HEADER_adr)

FVH_dirs = []
for something in os.listdir(os.getcwd()):
    if os.path.isdir(something):
        FVH_dirs.append(something)


while (n < sum_FVH):
	if (n == sum_FVH - 1):
		serch_file(VOLUME_HEADER_adr[n], get_segm_end(0), FVH_dirs[n])
		n = n + 1
	if (n < sum_FVH - 1): 
		serch_file(VOLUME_HEADER_adr[n], VOLUME_HEADER_adr[n + 1], FVH_dirs[n])
		n = n + 1

print("Is`s all!!!")