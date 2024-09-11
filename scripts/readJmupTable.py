from deps import *
import optparse
import logging
import capstone as cs

import blocks_pb2
import bbinfoconfig as bbl
from elftools.elf.elffile import ELFFile
from capstone import x86
from BlockUtil import *


logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level=logging.DEBUG)

textAddr = 0
textSize = 0
textOffset = 0
MD = None
#assemble_file_range = dict()

# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False
isGhidra = False



def isInRange(asm_file_range, addr):
    for (start, end) in asm_file_range.items():
        if addr >= start and addr < start + end:
            return True
    return False

        

def readJmpTablesGroundTruth(mModule, binary):
    """
    read jump tables from protobufs
    params:
        mModule: protobuf module
    returns:
        jmp tables: store the result of jmp tables
    """
    tmpFuncSet = set()
    result = dict()
    open_binary = open(binary, 'rb')
    content = open_binary.read()

    for func in mModule.fuc:
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        textEndOffset = textSize + textOffset
        for bb in func.bb:
            # If the number of basic block's successors number is bigger than 2
            if bb.type == BlockType.JUMP_TABLE and len(bb.instructions) > 0:
                successors = set()
                terminator_addr = bb.instructions[-1].va
                # if (bb.instructions[0].va + bb.size) in successors:
                #     successors.remove(bb.instructions[0].va + bb.size)
                logging.debug("Jump Table Basic Block at address %x with more than one successors" % bb.va)
                for suc in bb.child:
                    successors.add(suc.va)
                    logging.debug("Basic Block Successor at address %x" % suc.va)
                [successors.add(suc.va) for suc in bb.child]
                result[terminator_addr] = successors
    return result


def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                global textOffset
                pltSec = sec
                textSize = pltSec['sh_size']
                textAddr = pltSec['sh_addr']
                textOffset = pltSec['sh_offset']
                logging.info(".text section addr: 0x%x, size: 0x%x, offset: 0x%x" % (textSize, textAddr, textOffset))

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

def readAsmFileRange(mModule_shuffle):
    asm_file_range = dict()
    for layout in mModule_shuffle.layout:
        if layout.assemble_type == 2 and layout.offset not in asm_file_range:
            asm_file_range[layout.offset] = layout.bb_size
    asm_file_range = sorted(asm_file_range.items(), key=lambda x: x[0])

    # merge the range if it is continues
    merged_range = dict()
    pre_range = None
    for (start, size) in asm_file_range:
        if pre_range == None:
            pre_range = (start, size)
            continue

        # if the previous range is continues to current range, merge them
        if pre_range[0] + pre_range[1] == start:
            pre_range = (start, size + pre_range[1])
        else:
            merged_range[start] = size
            pre_range = (start, size)
    if pre_range != None:
        merged_range[pre_range[0]] = pre_range[1]
    for (start, end) in merged_range.items():
        logging.info("range from 0x%x to 0x%x" % (start, start + end))
    return merged_range

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile.lower():
            return base_offset
    # default offset is 0
    return 0

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binary", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("--elfarch", dest="elfarch", type="string", help="Binary arch e.g., x64", default="x64")
    parser.add_option("--elclass", dest="elfclass", type="int", help="Binary class e.g., 64", default=64)
    parser.add_option("--endian", dest="endian", help="Little endian", default=True)

    (options, args) = parser.parse_args()

    assert options.groundtruth != None, "Please input the ground truth file!"
    assert options.binary != None, "Please input the binary file!"

    readTextSection(options.binary)
    bbl.init(options.elfarch, options.elfclass, options.endian)
    elfclass = readElfClass(options.binary)
    MD = init_capstone(elfclass)
    PIE = isPIE(options.binary)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    mModule1 = blocks_pb2.module()

    try:
        f1 = open(options.groundtruth, 'rb')
        mModule1.ParseFromString(f1.read())
        f1.close()
    except IOError:
        logging.error("Could not open the file\n")
        exit(-1)

    truthTables = readJmpTablesGroundTruth(mModule1, options.binary)
