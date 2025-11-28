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


def xor(key, input_buffer): # Standard XOR decryption
    input_pos = 0
    key_length = len(key)
    output_buffer = bytearray()
    
    while (input_pos < len(input_buffer)):
        cur_buffer = input_buffer[input_pos:input_pos+key_length]
        output_buffer += bytes(a^b for (a,b) in zip(cur_buffer, key))
        input_pos += key_length
    
    return output_buffer


def de_lzw(input_buffer):
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
            dictionary[i] = i # Load the dictionary with all possible values

        dict_pos = 0
        while (dict_pos <= 0xFF): # Phase 1: input values to dictionary
            value_count = input_buffer[input_pos]
            input_pos += 1
            if (value_count >= 0x80): # Use as offset for current position
                dict_pos += value_count-0x7F
                if (dict_pos <= 0xFF):
                    value_count = 0
            if (dict_pos <= 0xFF):
                dict_off = 0 # Begin setting dictionary values
                while (dict_off <= value_count):
                    dictionary[dict_pos] = input_buffer[input_pos]
                    input_pos += 1
                    if (dict_pos != dictionary[dict_pos]):
                        dictionary[dict_pos+0x100] = input_buffer[input_pos] # Yes, we have a second dictionary
                        input_pos += 1 # Presumably for 16-bit values
                    dict_pos += 1
                    dict_off += 1
        
        value_count = ru16(input_buffer, input_pos)
        input_pos += 2 # Phase 2: write to output
        
        while (len(sym_stack) >= 1 or value_count > 0):
            if (len(sym_stack) < 1): # Use the current stacked symbol. Otherwise, the input byte
                cur_input = input_buffer[input_pos]
                input_pos += 1
                value_count -= 1
            else:
                cur_input = sym_stack.pop()
            if (cur_input == dictionary[cur_input]): # If we don't have a corresponding symbol, copy the byte
                output_buffer.append(cur_input)
            else:
                sym_stack.append(dictionary[cur_input+0x100])
                sym_stack.append(dictionary[cur_input])
                
    return output_buffer


def de_rle(input_buffer):
    if (ru32(input_buffer, 0) == 0):
        return -1 # This should not happen
        
    output_buffer = bytearray()
    other_buffer = bytearray(0x1000)
    head_pos = 4
    input_pos = head_pos
    input_pos += (ru32(input_buffer, 0)+7)>>3
    head_count = 0
    dictionary = bytearray(0x100)
    
    while (input_pos < len(input_buffer)):
        for i in range(0x100):
            dictionary[i] = i # Load the dictionary with all possible values
        
        curbyte = 2**(head_count) # The header is a filter by bit
        curbyte &= input_buffer[head_pos]
        if (curbyte == 0 and input_pos < len(input_buffer)-1):
            curshort = ru16(input_buffer, input_pos) # Load symbol
            input_pos += 2
            off = curshort//0x10 # The last 12 bytes are symbol offset
            if off == 0: # I can only assume this is possible
                return output_buffer
            length = (curshort&0x0F) # The first four bytes are symbol length
            
            for i in range(length+2):
                newbyte = dictionary[(off-1+i)%0x100] # Copy bytes
                if (len(output_buffer) > off-1+i): # I'm told this is a 'revolving window'?
                    newbyte = other_buffer[(off-1+i)%0x1000]
                    
                other_buffer[len(output_buffer)%0x1000] = newbyte
                output_buffer.append(newbyte)
        else:
            curbyte = input_buffer[input_pos] # Use and store symbol
            other_buffer[len(output_buffer)%0x1000] = curbyte
            output_buffer.append(curbyte)
            input_pos += 1
        
        head_count += 1
        if (head_count >= 8): # Increment header position once we're done with a byte
            head_pos += 1
            head_count = 0
    
    return output_buffer


def unpack_file(input_buffer, output_folder, output_name):
    output_folder = output_folder+"/"+output_name+f"_decompressed/"
    key = input_buffer[0x08:0x08+ru32(input_buffer,0x04)]
    file_pos = 0x08+len(key) # Set up XOR decryption
    section_size = []
    filenames = []
    file_props = []
    
    while (file_pos < len(input_buffer)-3):
        section_size.append(ru32(input_buffer, file_pos))
        file_pos += 0x04 # As far as I can tell, only the first two sections are important
    file_pos = section_size[0]
    
    listfile = input_buffer[file_pos:file_pos+section_size[1]]
    if (len(key) > 0): # Get the list of filenames and file properties
        listfile = xor(key, listfile)
    
    file_pos += section_size[1]
    for j in range(0, len(listfile), 0x40): # Serialize our file properties
        filenames.append(listfile[j:j+0x20].decode("utf-8").rstrip("\x00"))
        file_props.append([ru32(listfile, j+0x30),
        ru32(listfile, j+0x34),ru32(listfile, j+0x3C)])

    Path(output_folder).mkdir(parents=True,exist_ok=True)
    with open(output_folder+"packfiles.lst", "wb") as output:
        output.write(listfile) # Write the list file to its own file
        output.close()
    
    compfile = input_buffer[file_pos:len(input_buffer)] # We're done with the header now
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
            decomp_file = de_lzw(curfile)
        else:
            decomp_file = de_rle(curfile)
        
        filename = output_folder + filename # Write the output files
        if (type(decomp_file) is bytearray and len(decomp_file) > 0):
            with open(filename, "wb") as output:
                output.write(decomp_file)
                output.close()
            
            if (Path(filename).suffix == ".PAK"): # And now, unpacking within unpacking awaits you
                unpack_file(decomp_file, f"{Path(filename).parent}", Path(filename).stem)
    
    return 0


def xxxtract(index_buffer, data_buffer, output_folder, def_name):
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
            unpack_file(curfile, output_folder, Path(file_name).stem)
            
    print(f"File successfully extracted to {output_folder}!")
    return 0


parser = argparse.ArgumentParser(description='xxxHOLiC (PS2) File Extractor')
parser.add_argument("inpath", help="File Input (BIN/HD/PAK)")
parser.add_argument("-o", "--outpath", type=str, default="", help="Optional. The name used for the output folder.")
parser.add_argument("-r", "--recurse", type=bool, default=True, help="Do not extract packed files within the given file.")

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
        print(f"Found packed file {pakfile}!")
        pakfile = args.inpath
    else:
        print(f"File has unrecognized extension!")
        quit()
    
    outpath = "./"
    if len(args.outpath) > 0: # Outpath takes priority!!
        outpath += args.outpath
        if not outpath.endswith("/"):
            outpath += "/"
    else:
        outpath = (f"{Path(args.inpath).parent}/{Path(args.inpath).stem}")
    if not outpath.endswith("/"):
        outpath += "/"
    
    output_folder = outpath.rsplit("/",1)[0]+"/" # Split output into folder and filename
    output_file = outpath.rsplit("/",1)[1]
    Path(output_folder).mkdir(parents=True,exist_ok=True)
    
    if pakfile != None: # If we have a packed file, let's get unpacking
        with open(pakfile, "rb") as packed_file:
            pack_buffer = bytearray( packed_file.read() )
            print(f"Successfully opened {packed_file}!")
            unpack_file(pack_buffer, output_folder, output_file)
    else: # Otherwise, let's get extracting
        with open(hdfile, "rb") as index_file:
            with open(binfile, "rb") as data_file:
                index_buffer = bytearray( index_file.read() )
                data_buffer = bytearray( data_file.read() )
                print(f"Successfully opened {binfile}!")
                xxxtract(index_buffer, data_buffer, output_folder, output_file)
                data_file.close()
            index_file.close()