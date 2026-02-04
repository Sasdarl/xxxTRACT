import struct
import argparse
from pathlib import Path

def ru08(buf, offset):
    return struct.unpack("<B", buf[offset:offset+1])[0] # Some of these are unused but it's nice to have them around


def ru16(buf, offset):
    return struct.unpack("<H", buf[offset:offset+2])[0]


def ru32(buf, offset):
    return struct.unpack("<I", buf[offset:offset+4])[0]


def wu08(value):
    return struct.pack("<B", value)

def wu16(value):
    return struct.pack("<H", value)


def wu32(value):
    return struct.pack("<I", value)


def xor(key, input_buffer): # Standard XOR encryption/decryption
    if (len(key) <= 0):
        return input_buffer
    
    input_pos = 0
    key_length = len(key)
    output_buffer = bytearray()
    
    while (input_pos < len(input_buffer)):
        cur_buffer = input_buffer[input_pos:input_pos+key_length]
        output_buffer += bytes(a^b for (a,b) in zip(cur_buffer, key))
        input_pos += key_length
    
    return output_buffer


def de_huff(input_buffer):
    if (ru32(input_buffer, 0) == 0):
        return -1 # This should not happen

    output_buffer = bytearray()
    sym_stack = bytearray()
    file_length = ru32(input_buffer, 0) # In case the buffer size is wrong for some reason
    input_pos = 4
    dict_pos = 0
    output_pos = 0
    
    dictionary = bytearray(0x200)
    
    while (input_pos < len(input_buffer) and input_pos < file_length):
        for i in range(0x100):
            dictionary[i*2] = i # Load the dictionary with all possible values
        dict_pos = 0 # This keeps the second bytes of each value intact, which seems like a bug but we have to keep it in
        
        while (dict_pos < 0x100): # Phase 1: input values to dictionary
            value_count = input_buffer[input_pos]
            input_pos += 1
            if (value_count > 0x7F): # Use as offset for current position
                dict_pos += value_count-0x7F
                if (dict_pos < 0x100):
                    value_count = 0
            if (dict_pos >= 0x100):
                break
            
            for j in range(value_count+1):
                dictionary[dict_pos*2] = input_buffer[input_pos]
                input_pos += 1
                if (dict_pos != dictionary[dict_pos*2]):
                    dictionary[dict_pos*2+1] = input_buffer[input_pos]
                    input_pos += 1
                dict_pos += 1
        
        value_count = ru16(input_buffer, input_pos)
        input_pos += 2 # Phase 2: write to output
        
        while (len(sym_stack) >= 1 or value_count > 0):
            if (len(sym_stack) < 1): # Use the current stacked symbol. Otherwise, the input byte
                cur_input = input_buffer[input_pos]
                input_pos += 1
                value_count -= 1
            else:
                cur_input = sym_stack.pop()
            if (cur_input == dictionary[cur_input*2]): # If we don't have a corresponding symbol, copy the byte
                output_buffer.append(cur_input)
            else:
                sym_stack.append(dictionary[cur_input*2+1])
                sym_stack.append(dictionary[cur_input*2])
                
    return output_buffer


def re_huff(input_buffer): # We got there in the end
    input_pos = 0
    output_buffer = bytearray()
    dictionary = bytearray(0x200)
    sym_stack = bytearray()
    min_sym_use = 3 # This seems to be the most efficient value
    
    while (input_pos < len(input_buffer)):
        print(f"{len(output_buffer):X}")
        passes = 2 # Worst-case, the second pass does nothing
        
        for i in range(0x100):
            dictionary[i*2] = i # Load the dictionary with all possible values
        
        group_buffer = input_buffer[input_pos::] # Store a temporary buffer for the input we cover with the current dict
        group_pos = 0
        while (passes > 0):
            use_byte_count = 0
            use_byte_table = bytearray(0x200)
            use_sym_table = bytearray()
            
            while (group_pos < len(group_buffer) and use_byte_count + len(use_sym_table) < 0x100): # Phase 1: assess symbol usage
                cur_byte = group_buffer[group_pos]
                
                if (use_byte_table[cur_byte] == 0):
                    use_byte_count += 1
                if (use_byte_table[cur_byte] < 0xFE):
                    use_byte_table[cur_byte] += 1 # Reserving 0xFF for processed symbols
                if (group_pos > 0 and group_pos < len(group_buffer)-1): # Do not read from beyond the end of the buffer
                    cur_short = ru16(group_buffer, group_pos-1)
                    short_pos = 0
                    while((short_pos%2 > 0 and short_pos > 0) or short_pos == 0): # Gather 16-bit symbols
                        short_pos = sym_stack.find(wu16(cur_short), short_pos+1)
                    if (short_pos >= 0 and use_sym_table[short_pos>>1] < 0xFE): # Increment 16-bit sym use
                        use_sym_table[short_pos>>1] += 1
                    else:
                        sym_stack += wu16(cur_short)
                        use_sym_table.append(1)
                group_pos += 1
            
            group_buffer = group_buffer[0:group_pos]
        
            while (len(sym_stack) > 0): # Phase 2: input dictionary values
                cur_sym = ru16(sym_stack, 0)
                cur_sym_use = use_sym_table[0]
                
                if (cur_sym_use >= min_sym_use): # Symbols that fall below our threshold will be kept as-is
                    dict_rep = -1
                    while (dict_rep < 0 or dict_rep == cur_sym&0xFF):
                        dict_rep = use_byte_table.find(0, dict_rep+1) # Only replace unused bytes!
                    if (dict_rep >= 0):
                        use_byte_table[dict_rep] = 0xFF # Mark this symbol as used (very important)
                        dictionary[dict_rep*2:dict_rep*2+2] = wu16(cur_sym)
                        group_buffer = group_buffer.replace(wu16(cur_sym),wu08(dict_rep)) # We can replace directly in our buffer
                sym_stack = sym_stack[2::]
                use_sym_table = use_sym_table[1::]
            passes -= 1
        input_pos += group_pos

        dict_pos = 0
        last_dict_pos = 0
        while (dict_pos < 0x100): # Phase 3: build dictionary header
            value_count = 0
            if (dict_pos-last_dict_pos >= 0x7F): # Since offsets start at 0x80, they can't go too far
                output_buffer.append(0x7F+0x7F)
                last_dict_pos += 0x7F
                value_count = 1
            elif (ru16(dictionary,dict_pos*2) != dict_pos):
                if (dict_pos-last_dict_pos > 0):
                    output_buffer.append(dict_pos-last_dict_pos+0x7F) # As long as our pos is an 8-bit value, we have to put in one symbol
                    last_dict_pos = dict_pos
                    value_count = 1
                else:
                    while (dict_pos+value_count < 0xFF and value_count < 0x7F and ru16(dictionary, (dict_pos+value_count)*2) != dict_pos+value_count):
                        value_count += 1 # Count up the values we have to replace
                    if (value_count > 0):
                        output_buffer.append(value_count-1) # Only add the count if we're actually going to use it!
            if (value_count == 0): # If we didn't get anything, keep going through the dictionary
                dict_pos += 1
            if (dict_pos >= 0x100): # If we're out of 8-bit range, we're DONE with the dictionary header
                break
            for i in range(value_count):
                if (dict_pos < 0xFF and dictionary[dict_pos*2] != dict_pos): # Don't replace symbols we're using for other symbols
                    output_buffer += dictionary[dict_pos*2:dict_pos*2+2]
                else:
                    output_buffer.append(dict_pos)
                dict_pos += 1
                last_dict_pos = dict_pos
        if (dict_pos > last_dict_pos): # Ensure the header reaches 0x100 or higher so it can end
            output_buffer.append(dict_pos-last_dict_pos+0x7F)
        output_buffer += wu16(len(group_buffer)) # Prepend size of data section
        output_buffer += group_buffer
    
    output_buffer = wu32(len(output_buffer)) + output_buffer
    return output_buffer


def de_rle(input_buffer):
    if (ru32(input_buffer, 0) == 0):
        return -1 # This should not happen
        
    output_buffer = bytearray()
    sym_buffer = bytearray(0x1000)
    head_pos = 4
    input_pos = head_pos
    input_pos += (ru32(input_buffer, 0)+7)>>3
    head_count = 0

    for i in range(0x100):
        sym_buffer[i] = i # Load the dictionary with all possible values
            
    while (input_pos < len(input_buffer)):
        curbyte = 2**(head_count) # The header is a filter by bit
        curbyte &= input_buffer[head_pos]
        if (curbyte == 0 and input_pos < len(input_buffer)-1):
            curshort = ru16(input_buffer, input_pos) # Load symbol
            input_pos += 2
            off = curshort//0x10 # The last 12 bits are symbol offset
            if off == 0: # I can only assume this is possible
                return output_buffer
            length = (curshort&0x0F) # The first four bits are symbol length
            
            for i in range(length+2):
                newbyte = sym_buffer[(off-1+i)%0x1000] # Copy bytes
                sym_buffer[len(output_buffer)%0x1000] = newbyte
                output_buffer.append(newbyte)
        else:
            curbyte = input_buffer[input_pos] # Use and store symbol
            sym_buffer[len(output_buffer)%0x1000] = curbyte
            output_buffer.append(curbyte)
            input_pos += 1
        
        head_count += 1
        if (head_count >= 8): # Increment header position once we're done with a byte
            head_pos += 1
            head_count = 0
    return output_buffer


def re_rle(input_buffer): # Compression is pain
    output_buffer = bytearray()
    head_buffer = bytearray()
    data_buffer = bytearray()
    sym_buffer = bytearray(0x1000)
    head_byte = 0
    head_bit = 0
    input_pos = 0
    sync_count = 0

    for i in range(0x100):
        sym_buffer[i] = i # Load the dictionary with all possible values
    
    while (input_pos < len(input_buffer)):
        curbyte = input_buffer[input_pos]
        for i in range(input_pos%0x1000, 0x1000):
            sync_count = 0
            while (sync_count < 15 
            and input_pos+sync_count < len(input_buffer) 
            and input_buffer[input_pos+sync_count] == sym_buffer[(i+sync_count)%0x1000]):
                sync_count += 1
            if (i == 0x1000-1 and sync_count <= 2):
                sym_buffer[input_pos%0x1000] = curbyte
                data_buffer.append(curbyte)
                head_byte += 2**head_bit # The header is a filter by bit
                input_pos += 1
                break
            elif (sync_count > 2):
                for j in range(sync_count): # Copy bytes
                    sym_buffer[(input_pos+j)%0x1000] = input_buffer[input_pos+j]
                data_buffer.extend(wu16((sync_count-2) + ((i+1)%0x1000)*0x10))
                input_pos += sync_count
                break

        head_bit += 1
        if (head_bit >= 8): # Increment header position once we're done with a byte
            head_buffer.append(head_byte)
            head_byte = 0
            head_bit = 0
    
    if (head_bit > 0):
        head_buffer.append(head_byte)
    
    output_buffer.extend(wu32( (len(head_buffer)<<3)-7 ))
    output_buffer.extend(head_buffer)
    output_buffer.extend(data_buffer)
    return output_buffer


def buildholic(input_folder, output_folder, output_file, recurse):
    if (not Path(input_folder+"/FILENAME.LST").is_file()):
        print("Could not find file list!")
        return -1 # We need this list to know which compression to use

    filenames = []
    head_buffer = bytearray()
    output_buffer = bytearray()
    contains_packed = False
    
    with open(input_folder+"/FILENAME.LST", "r") as list_file:
        filenames = list_file.readlines()
        list_file.close()
    with open(input_folder+"/FILENAME.LST", "rb") as list_file:
        filelist = bytearray( list_file.read() )
        output_buffer.extend(filelist)
        head_buffer.extend(wu32(len(filelist)))
        while (len(output_buffer)%0x800 > 0):
            output_buffer.append(0xFF)
        list_file.close()
    
    for i in range(1, len(filenames)):
        curname = filenames[i].rsplit('\n',1)[0]
        with open(input_folder+"/"+curname, "rb") as input_file:
            input_buffer = bytearray( input_file.read() )
            if (recurse and filenames[i].endswith(".PAK\n")):
                print(f"Repacking {curname}...")
                contains_packed = True
                input_buffer = repack_file(input_folder+"/"+Path(filenames[i]).stem+"_decompressed", input_folder, filenames[i], recurse, False)
            
            output_buffer.extend(input_buffer)
            head_buffer.extend(wu32(len(input_buffer)))
            while (len(output_buffer)%0x800 > 0):
                output_buffer.append(0xFF)

            input_file.close()

    outfile = output_folder + "/" + output_file
    outfile2 = output_folder + "/" + Path(output_file).stem + ".hd"
    with open(outfile, "wb") as output:
        output.write(output_buffer)
        output.close()
    with open(outfile2, "wb") as output:
        output.write(head_buffer)
        output.close()

    print(f"File successfully rebuilt to {outfile}!")
    return output_buffer


def repack_file(input_folder, output_folder, output_file, recurse, write=True):
    key = b""
    
    if (not Path(input_folder+"/packfiles.lst").is_file()):
        print("Could not find file list!")
        return -1 # We need this list to know which compression to use
        
    filenames = []
    file_props = []
    output_buffer = bytearray()
    contains_packed = False
    
    with open(input_folder+"/packfiles.lst", "rb") as list_file:
        list_buffer = bytearray( list_file.read() )
        for j in range(0, len(list_buffer), 0x40): # Serialize our file properties
            filenames.append(list_buffer[j:j+0x20].decode("utf-8").rstrip("\x00"))
            file_props.append([ru32(list_buffer, j+0x30),
            ru32(list_buffer, j+0x34),ru32(list_buffer, j+0x3C)])
        list_file.close()
    
    for i in range(0, len(filenames)):
        with open(input_folder+"/"+filenames[i], "rb") as input_file:
            input_buffer = bytearray( input_file.read() )
            if (filenames[i].endswith(".PAK")):
                contains_packed = True
                if (recurse):
                    print(f"Repacking {filenames[i]}...")
                    contains_packed = True
                    repack_file(input_folder+"/"+Path(filenames[i]).stem+"_decompressed", input_folder, filenames[i], recurse, False)
            
            file_props[i][0] = len(output_buffer)
            file_props[i][1] = len(input_buffer)
                        
            print(filenames[i])
            if file_props[i][2]%0x10 == 2:
                input_buffer = re_huff(input_buffer) # We do this now.
            if file_props[i][2]%0x10 == 1:
                input_buffer = re_rle(input_buffer)
            input_buffer = xor(key, input_buffer)
            output_buffer.extend(input_buffer)
            input_file.close()
    
    head_buffer = bytearray()
    head_buffer.extend(b"PACK")
    head_buffer.extend(wu32(len(key)))
    head_buffer.extend(key)
    head_buffer.extend(wu32(0x28+len(key)))
    head_buffer.extend(wu32(len(filenames)*0x40))
    head_buffer.extend(wu32(0x28+len(key)+(len(filenames)*0x40)))
    head_buffer.extend(wu32(len(output_buffer)))
    head_buffer.extend(wu32(contains_packed))
    head_buffer.extend(wu32(len(filenames)))
    head_buffer.extend(wu32(0x40))
    head_buffer.extend(bytearray(0x04))
    for i in range(len(filenames)):
        file_head = bytearray()
        file_head.extend(filenames[i].encode())
        if (len(filenames[i]) < 0x20):
            file_head.extend(bytearray(0x20-len(filenames[i])))
        file_head.extend(bytearray(0x10))
        file_head.extend(wu32(file_props[i][0]))
        if (i < len(filenames)-1):
            file_head.extend(wu32(file_props[i+1][0]-file_props[i][0]))
        else:
            file_head.extend(wu32(len(output_buffer)-file_props[i][0]))
        file_head.extend(wu32(file_props[i][1]))
        file_head.extend(wu32(file_props[i][2]))
        file_head = xor(key, file_head)
        head_buffer.extend(file_head)
        
    output_buffer = head_buffer+output_buffer
    
    if (write):
        outfile = output_folder + "/" + output_file
        with open(outfile, "wb") as output:
            output.write(output_buffer)
            output.close()
    
    return output_buffer


def unpack_file(input_buffer, output_folder, output_name, recurse):
    output_folder = output_folder+"/"+output_name+"/"
    key = input_buffer[0x08:0x08+ru32(input_buffer,0x04)]
    file_pos = 0x08+len(key) # Set up XOR decryption
    filenames = []
    file_props = []

    index_pos = ru32(input_buffer,file_pos)
    index_size = ru32(input_buffer,file_pos+0x04)
    data_pos = ru32(input_buffer,file_pos+0x08)
    data_size = ru32(input_buffer,file_pos+0x0C)
    
    listfile = input_buffer[index_pos:index_pos+index_size]
    if (len(key) > 0): # Get the list of filenames and file properties
        listfile = xor(key, listfile)
    
    file_pos += data_size
    for j in range(0, len(listfile), 0x40): # Serialize our file properties
        filenames.append(listfile[j:j+0x20].decode("utf-8").rstrip("\x00"))
        file_props.append([ru32(listfile, j+0x30),
        ru32(listfile, j+0x34),ru32(listfile, j+0x3C)])

    Path(output_folder).mkdir(parents=True,exist_ok=True)
    with open(output_folder+"packfiles.lst", "wb") as output:
        output.write(listfile) # Write the list file to its own file
        output.close()
    
    compfile = input_buffer[data_pos:data_pos+data_size] # We're done with the header now
    for i in range(0, len(filenames)):
        curfile = compfile[file_props[i][0]:file_props[i][0]+file_props[i][1]] # Get current file
        
        if (len(filenames) > i): # If we don't have a filename, use a placeholder
            filename = filenames[i]
        else:
            filename = f"data{i-1:02d}.bin"
        print(f"    /{filename}; 0x{len(curfile):X}") # Print name and size
        
        if (len(key) > 0): # If we have a key available, perform XOR
            curfile = xor(key, curfile)

        if (file_props[i][2] % 0x10 == 2): # Use properties to select decompression algorithm
            decomp_file = de_huff(curfile)
        elif (file_props[i][2] % 0x10 == 1):
            decomp_file = de_rle(curfile)
        else:
            decomp_file = curfile
        
        filename = output_folder + filename # Write the output files
        if (type(decomp_file) is bytearray and len(decomp_file) > 0):
            with open(filename, "wb") as output:
                output.write(decomp_file)
                output.close()
            with open(filename+".TEMP", "wb") as tempput:
                tempput.write(curfile)
                tempput.close()
            
            if (recurse and Path(filename).suffix == ".PAK"): # And now, unpacking within unpacking awaits you
                unpack_file(decomp_file, f"{Path(filename).parent}", Path(filename).stem+"_decompressed", recurse)
    
    return decomp_file


def xxxtract(index_buffer, data_buffer, output_folder, def_name, recurse):
    index_start = 0
    data_pos = 0
    files = len(index_buffer) // 4
    filenames = []
    file_props = []
    
    if (data_buffer[0:8] == b"FILENAME"): # BIN files start with a file list
        filename_len = ru32(index_buffer,0x00)
        filenames = data_buffer[0:filename_len].decode("utf-8")
        filenames = filenames.splitlines() # We treat this separately to get filenames and file properties

        index_start += 1
        data_pos += filename_len # We're not worried about what else is there
        data_pos += int((0x800-(filename_len%0x800))%0x800)
        
        with open(Path(output_folder+filenames[0]),"wb") as output:
            output.write(data_buffer[0:filename_len]) # Yes, this file contains its own name
            output.close()

    for i in range(index_start,files):
        filelen = ru32(index_buffer, i*4)
        curfile = data_buffer[data_pos:data_pos+filelen] # Get file
        
        if (len(filenames) > i): # If we don't have filenames, use a placeholder
            file_name = filenames[i]
        else:
            file_name = f"{def_name}[{i}].bin"
        
        data_pos += filelen
        data_pos += (0x800-(filelen%0x800))%0x800
        print(f"{file_name }; 0x{filelen:X}") # Print name and size of each file

        with open(output_folder+file_name, "wb") as output:
            output.write(curfile)
            output.close()
        
        if (curfile[0:4] == b"PACK"): # If the file's packed, let's unpack it
            unpack_file(curfile, output_folder, Path(file_name).stem+"_decompressed", recurse)
            
    print(f"File successfully extracted to {output_folder}!")
    return 0


parser = argparse.ArgumentParser(description='xxxHOLiC (PS2) File Extractor')
parser.add_argument("inpath", help="File Input (BIN/HD/PAK)")
parser.add_argument("-o", "--outpath", type=str, default="", help="Optional. The name used for the output folder or file.")
parser.add_argument("-r", "--recurse", action="store_true", default=False, help="Extract/rebuild packed files within the given file.")

args = parser.parse_args()
hdfile = None
binfile = None
pakfile = None

if Path(args.inpath).is_file() and not Path(args.inpath).is_dir():
    print(f"Found file {args.inpath}...")
    if Path(args.inpath).suffix == ".hd": # These files come in pairs
        hdfile = args.inpath
        if Path(args.inpath.rsplit(".",1)[-2] + ".bin").is_file():
            binfile = Path(args.inpath.rsplit(".",1)[-2] + ".bin")
            print(f"Found BIN file {binfile}!")
        else:
            print(f"Could not find BIN file for {args.inpath}!")
            quit()
    elif Path(args.inpath).suffix == ".bin":
        binfile = args.inpath
        if Path(args.inpath.rsplit(".",1)[-2] + ".hd").is_file():
            hdfile = Path(args.inpath.rsplit(".",1)[-2] + ".hd")
            print(f"Found HD file {hdfile}!")
        else:
            print(f"Could not find HD file for {args.inpath}!")
            quit()
    elif Path(args.inpath).suffix == ".pak": # Except packed files. These don't come in pairs
        pakfile = args.inpath
        print(f"Packed file detected!")
    else:
        print(f"File has unrecognized extension!")
        quit()
    
    outpath = "./"
    if len(args.outpath) > 0: # Outpath takes priority!!
        outpath += args.outpath
    else:
        outpath = (f"{Path(args.inpath).parent}/{Path(args.inpath).stem}")
        if (pakfile != None):
            outpath += "_decompressed"
    if not outpath.endswith("/"):
        outpath += "/"
    
    output_folder = outpath.rsplit("/",1)[0]+"/" # Split output into folder and filename
    output_file = outpath.rsplit("/",1)[1]
    Path(output_folder).mkdir(parents=True,exist_ok=True)
    
    if pakfile != None: # If we have a packed file, let's get unpacking
        with open(pakfile, "rb") as packed_file:
            pack_buffer = bytearray( packed_file.read() )
            print(f"Successfully opened {pakfile}!")
            unpack_file(pack_buffer, output_folder, output_file, args.recurse)
    else: # Otherwise, let's get extracting
        with open(hdfile, "rb") as index_file:
            with open(binfile, "rb") as data_file:
                index_buffer = bytearray( index_file.read() )
                data_buffer = bytearray( data_file.read() )
                print(f"Successfully opened {binfile}!")
                xxxtract(index_buffer, data_buffer, output_folder, output_file, args.recurse)
                data_file.close()
            index_file.close()
else:
    if Path(args.inpath).is_dir():
        infolder = Path(args.inpath)
        output_folder = "./"
        output_file = infolder.stem.rsplit("_",1)[0] # Remove "_decompressed"
    
        if len(args.outpath) > 0: # Outpath takes priority!!
            output_file = args.outpath
            if (output_file.find("/") >= 0):
                output_folder = output_file.rsplit("/",1)[0]+"/" # Split output into folder and filename
                output_file = output_file.rsplit("/",1)[1]
        if (infolder.stem.find("_decompressed") and output_file.find(".") < 0):
            output_file = f"{output_file}.pak" # Add suffix if necessary
        else:
            if (output_file.find(".") < 0):
                output_file = f"{output_file}.bin"
        print(output_file)
        Path(output_folder).mkdir(parents=True,exist_ok=True)
        
        if (Path(args.inpath+"/FILENAME.LST").is_file()):
            buildholic(args.inpath, output_folder, output_file, args.recurse)
        else:
            repack_file(args.inpath, output_folder, output_file, args.recurse)
    else:
        print("Unable to find input file/folder!")
        quit()