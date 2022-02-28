from binaryninja import *
from binaryninja.binaryview import BinaryView
from binaryninja.platform import Platform

#  binja doesn't want to load mods in a plugin's dir
#  so hopefully we can just hack that in manually
#  We do this after importing binaryninja, because in my local workspace I embed a copy of
#       the binaryninja API so my IDE can handle intellisense
#       This wont interfere since binja wont see that dir properly

this_script = os.path.realpath(__file__)
this_dir = os.path.dirname(this_script)
sys.path.insert(0, this_dir)
sys.path.insert(0, this_dir + os.path.sep + 'ktool')

from io import BytesIO

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.dyld.dyld_context import DyldContext

from DyldExtractor.converter import (
    slide_info,
    macho_offset,
    linkedit_optimizer,
    stub_fixer,
    objc_fixer
)

import ktool


def internal_print_rewrite(msg):
    log.log(LogLevel.InfoLog, msg)


print = internal_print_rewrite


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


# noinspection PyAbstractClass
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
        mod_index = get_choice_input(f'Found {len(self.cache_handler.images)} Images', f'Select Image',
                                     self.cache_handler.images)
        mod = self.cache_handler.images[mod_index]
        image = self.cache_handler.image_map[mod]

        _macho_offset, context = self.cache_handler.dyld_context.convertAddr(image.address)
        macho_ctx = MachOContext(context.fileObject, _macho_offset, True)

        extraction_ctx = ExtractionContext(self.cache_handler.dyld_context, macho_ctx)

        slide_info.processSlideInfo(extraction_ctx)
        linkedit_optimizer.optimizeLinkedit(extraction_ctx)
        stub_fixer.fixStubs(extraction_ctx)
        objc_fixer.fixObjC(extraction_ctx)

        write_procedures = macho_offset.optimizeOffsets(extraction_ctx)

        virt_macho = BytesIO()

        # Write the MachO file
        for procedure in write_procedures:
            virt_macho.seek(0)
            virt_macho.seek(procedure.writeOffset)
            virt_macho.write(
                procedure.fileCtx.getBytes(procedure.readOffset, procedure.size)
            )

        virt_macho.seek(0)

        image = ktool.load_image(virt_macho)

        for segment in image.segments.values():
            segment: ktool.macho.Segment = segment
            seg_dat = image.get_bytes_at(segment.file_address, segment.size)
            # We can map all of these as RWX or ---, it makes no difference. 
            # This view wont be analyzing, and MachO or ObjectiveNinja will properly map them. 
            self.add_auto_segment(segment.vm_address, segment.size, segment.file_address, segment.size, SegmentFlag.SegmentReadable)
            self.write(segment.vm_address, bytes(seg_dat))

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
