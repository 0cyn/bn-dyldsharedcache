
from binaryninja import *

from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol

#  k, binja doesn't want to load mods in a plugin's dir 
#  so hopefully we can just hack that in manually
import os.path 
this_script = os.path.realpath(__file__)
this_dir = os.path.dirname(this_script)
sys.path.insert(0, this_dir)
sys.path.insert(0, this_dir + os.path.sep + 'ktool')

from io import BytesIO


from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.dyld.dyld_context import DyldContext

from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_image_info
)

from DyldExtractor.converter import (
	slide_info,
	macho_offset,
	linkedit_optimizer,
	stub_fixer,
	objc_fixer
)

import ktool

def internal_print_rewrite(msg):
    log.log(1, msg)

print = internal_print_rewrite

def list_images(dsc_filename):
    
    dsc_modules = []

    with open(dsc_filename, "rb") as f:
        print('Opening Context')
        dyldCtx = DyldContext(f)

        print(f'Found {len(dyldCtx.images)} images')

        # enumerate images, create a map of paths and images
        imageMap = {}
        print('Iterating Images')
        for imageData in dyldCtx.images:

            path = dyldCtx.readString(imageData.pathFileOffset)
            path = path[0:-1]  # remove null terminator
            path = path.decode("utf-8")

            dsc_modules.append(path)
    
    return dsc_modules

class DyldCacheHander:
    def __init__(self, filename):
        self.filename = filename
        self.images = []
        self.image_map = {}

        self.fp = open(filename, 'rb')
        self.dyld_context = None
    
    def populate_image_list(self):
        self.dyld_context = DyldContext(self.fp)
        for imageData in self.dyld_context.images:

            path = self.dyld_context.readString(imageData.pathFileOffset)
            path = path[0:-1]  # remove null terminator
            path = path.decode("utf-8")

            self.images.append(path)
            self.image_map[path] = imageData


class DyldSharedCacheView(BinaryView):
    name = "DyldSharedCache"
    long_name = "Dyld Shared Cache Loader"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.cache_handler = DyldCacheHander(data.file.filename)

    def init(self):

        # TODO: not hardcode
        self.platform = Platform[f"mac-aarch64"]

        self.cache_handler.populate_image_list()
        mod_index = get_choice_input(f'Found {len( self.cache_handler.images)} Images', f'Select Image', self.cache_handler.images)
        mod = self.cache_handler.images[mod_index]
        image = self.cache_handler.image_map[mod]

        machoOffset, context = self.cache_handler.dyld_context.convertAddr(image.address)
        machoCtx = MachOContext(context.fileObject, machoOffset, True)
        
        extractionCtx = ExtractionContext(self.cache_handler.dyld_context, machoCtx)

        slide_info.processSlideInfo(extractionCtx)
        linkedit_optimizer.optimizeLinkedit(extractionCtx)
        stub_fixer.fixStubs(extractionCtx)
        objc_fixer.fixObjC(extractionCtx)

        writeProcedures = macho_offset.optimizeOffsets(extractionCtx)

        virt_macho = BytesIO()

        # Write the MachO file
        for procedure in writeProcedures:
            virt_macho.seek(0)
            virt_macho.seek(procedure.writeOffset)
            virt_macho.write(
                procedure.fileCtx.getBytes(procedure.readOffset, procedure.size)
            )

        virt_macho.seek(0)

        # there is finally a valid reason for me writing ktool to support BytesIO! :)
        image = ktool.load_image(virt_macho)

        # ! if we made it this far, we have a valid macho. yay!

        for segment in image.segments.values():
            segment: ktool.macho.Segment = segment
            bn_flags = 0
            seg_dat = image.get_bytes_at(segment.file_address, segment.size)
            # We can map all of these as RWX or ---, it makes no difference. 
            # This view wont be analyzing, and MachO or ObjectiveNinja will properly map them. 
            self.add_auto_segment(segment.vm_address, segment.size, segment.file_address, segment.size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
        
            self.write(segment.vm_address, bytes(seg_dat))

        for function_start in image.function_starts:
            self.add_function(function_start)
            if function_start in image.symbols:
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, function_start, image.symbols[function_start].fullname))
        
        show_message_box('Image Loaded!', 'Please Swap the View type (top left) from "DyldCacheExtractor" to "Mach-O"', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        
        self.abort_analysis() 

        return True


    @classmethod
    def is_valid_for_data(cls, data):
        hdr = data.read(0, 16)
        if len(hdr) < 16:
            return False
        if b'dyld_v1' not in hdr:
            return False
        return True