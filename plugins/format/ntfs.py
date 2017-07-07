from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
import PyQt4
from cemu import *

import sys, os
import DisasmViewMode

class FsNtfs(FileFormat):
    name = 'fs_ntfs'
    priority = 5

    lock = 0
    def recognize(self, dataModel):
        self.dataModel = dataModel
        if self.dataModel.getWORD(510) != 0xAA55:
            # check if valid boot record
            return False

        if self.dataModel.getDWORD(3) != 0x5346544e:
            # check if NTFS magic
            return False

        # this will actually hit the same as mbr plugin, but this one has bigger priority

        return True

    def _encodeutf16(self, s):
        return '\x00'.join(s)

    def init(self, viewMode, parent):
        self._viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.INDXbrush = QtGui.QBrush(QtGui.QColor(128, 128, 0))
        self.SpecialFilebrush = QtGui.QBrush(QtGui.QColor(128, 0, 128))
        self.yellowPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(0, 255, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))        


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'MZ', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'PE\x00\x00', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\x55\xAA', brush=self.MZbrush, pen=self.greenPen)


        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$MFT'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$MFTMirr'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Boot'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$LogFile'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$BadClus'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$AttrDef'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Bitmap'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Extend'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Secure'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Volume'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$UpCase'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Reparse'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Repair'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Config'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Deleted'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Repair'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Quota'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$TxfLog'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$TxfLog.blf'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$RmMetadata'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$I30'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$ObjId'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Tops'), brush=self.SpecialFilebrush, pen=self.yellowPen)



        self.textDecorator = HighlightPrefix(self.textDecorator, 'FILE', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'INDX', brush=self.INDXbrush, pen=self.greenPen)


        # first jump
        self.textDecorator = RangePen(self.textDecorator, 0, 2, pen=self.yellowPen, ignoreHighlights=True)

        # ntfs
        self.textDecorator = RangePen(self.textDecorator, 3, 8, pen=self.greenPen, ignoreHighlights=True)


        self.textDecorator = HighlightWideChar(self.textDecorator)

        self._viewMode.setTransformationEngine(self.textDecorator)

        # $BOOT
        self._viewMode.selector.addSelection((0x0B, 0x48 + 8, QtGui.QBrush(QtGui.QColor(125, 175, 150)), 0.4), type=TextSelection.SelectionType.PERMANENT)

        # compute $MFT cluster
        self.lcn_of_mft = self.dataModel.getQWORD(0x30)
        self.sectors_per_cluster = self.dataModel.getBYTE(0x0D)
        self.bytes_per_sector = self.dataModel.getWORD(0x0B)
        self.clusters_per_mft_record = self.dataModel.getDWORD(0x40)

        # file record
        start_mft = self.lcn_of_mft * self.sectors_per_cluster * self.bytes_per_sector
        self.file_record_size = 1024 #!FIXME #self.clusters_per_mft_record * self.sectors_per_cluster * self.bytes_per_sector

        if start_mft > self.dataModel.getDataSize():
            # incomplete
            # should be logged
            return True

        if self.lock == 1:
            return True

        self.lock = 1

        mft_data_runs = self._get_mft_data_runs()

        # dump $MFT
        file_record_start = 0
        for data_run in mft_data_runs:
            file_record_start = self._dump_mft(data_run, file_record_start)


        return True



    def _dump_mft(self, datarun, file_record_start):
        n, lcn = datarun

        start_mft = lcn * self.sectors_per_cluster * self.bytes_per_sector
        mft_size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

        n_file_records = mft_size_in_bytes / self.file_record_size

        print 'Total file records #{}'.format(n_file_records)

        for i in range(n_file_records):

            print ''
            print '======================================================================================================'
            print 'FILE_RECORD #{0}'.format(file_record_start + i)

            file_record = start_mft + i*self.file_record_size
            fr = file_record
            off_first_attr = self.dataModel.getWORD(file_record+0x14)
            data = self.dataModel

            magic = data.getStream(fr + 0x00, fr + 0x04)
            print 'magic: {}'.format(magic)
            if magic != "FILE":
                continue

            #ofs_up_seq = data.getWORD(fr + 0x04)
            #print 'Offset to the Update Sequence: 0x{:1X}'.format(ofs_up_seq)

            flags = data.getWORD(fr + 0x16)
            print 'Flags: 0x{:1X}'.format(flags)

            size_upd_seq = data.getWORD(fr + 0x06)

            real_size = data.getDWORD(fr + 0x18)
            print 'Real size of file record: 0x{:1X}'.format(real_size)

            allocated_size = data.getDWORD(fr + 0x1c)
            print 'Allocated size of file record: 0x{:0X}'.format(allocated_size)

            file_reference = data.getQWORD(fr + 0x20)
            print 'File reference to the base FILE record: 0x{:0X}'.format(file_reference)

            next_attribute_id = data.getWORD(fr + 0x28)
            print 'Next Attribute Id: 0x{:0X}'.format(next_attribute_id)



            print ''

            ao = fr + off_first_attr 
            while 1:
                std_attr_type = data.getDWORD(ao + 0x00)
                if std_attr_type == 0xFFFFFFFF:
                    break

                attrs = {0x10 : "$STANDARD_INFORMATION", 0x30: "$FILE_NAME", 0x80: "$DATA", 0xB0: "$BITMAP", 0x60: "$VOLUME_NAME", 0x70: "$VOLUME_INFORMATION",
                         0x50 : "$SECURITY_DESCRIPTOR", 0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION", 0x100: "$LOGGED_UTILITY_STREAM"}

                # standard attribute header
                print 'Attribute type: {0}'.format(attrs[std_attr_type])

                attr_length = data.getDWORD(ao + 0x04)
                print 'Length: 0x{:0X}'.format(attr_length)

                non_resident_flag = data.getBYTE(ao + 0x08)
                print 'Non-resident flag: 0x{:0X}'.format(non_resident_flag)

                attr_name_length = data.getBYTE(ao + 0x09)
                print 'Name length: 0x{:0X}'.format(attr_name_length)

                c_start = ao
                c_end = ao + attr_length
                # let's color some attributes
                self._viewMode.selector.addSelection((c_start, c_end, QtGui.QBrush(QtGui.QColor(200, 9, 6)), 0.3), type=TextSelection.SelectionType.IF_CURSOR_IN_RANGE)

                if not non_resident_flag and not attr_name_length:
                    offset_to_attribute = data.getWORD(ao + 0x14)

                    attr_length_2 = data.getDWORD(ao + 0x10)
                    print 'Length of the attribute: 0x{:0X}'.format(attr_length_2)


                if not non_resident_flag and  attr_name_length:
                    offset_to_attribute = data.getWORD(ao + 0x14)

                    attr_name = data.getStream(ao + 0x18, ao + 0x18 + 2 * attr_name_length)
                    attr_name = ''.join([chr(c) for c in attr_name if c != 0])
                    print 'resident, named'
                    print 'Attribute name: {0}'.format(attr_name)


                    attr_length_2 = data.getDWORD(ao + 0x10)
                    print 'Length of the attribute: 0x{:0X}'.format(attr_length_2)



                if non_resident_flag and not attr_name_length:
                    starting_vcn = data.getQWORD(ao + 0x10)
                    print 'Starting VCN 0x{:0X}'.format(starting_vcn)

                    last_vcn = data.getQWORD(ao + 0x18)
                    print 'Last VCN 0x{:0X}'.format(last_vcn)

                    attr_real_size = data.getQWORD(ao + 0x30)
                    print 'Real size of the attribute 0x{:0X}'.format(attr_real_size)
                    attr_length_2 = attr_real_size

                    # offset to datarun
                    offset_to_attribute = data.getWORD(ao + 0x20) 

                    print 'data runs...'
                    s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - 0x40)
                    for k in s:
                        print '0x{:02x}'.format(k),

                    print ''

                    data_runs = self._decode_data_runs(s)

                    for data_run in data_runs:
                        n, lcn = data_run

                        file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                        size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                        print '0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes)




                if non_resident_flag and  attr_name_length:
                    starting_vcn = data.getQWORD(ao + 0x10)
                    print 'non-resident, named'
                    print 'Starting VCN 0x{:0X}'.format(starting_vcn)

                    last_vcn = data.getQWORD(ao + 0x18)
                    print 'Last VCN 0x{:0X}'.format(last_vcn)

                    attr_name = data.getStream(ao + 0x40, ao + 0x40 + 2 * attr_name_length)
                    attr_name = ''.join([chr(c) for c in attr_name if c != 0])
                    
                    print 'Attribute name: {0}'.format(attr_name)

                    attr_real_size = data.getQWORD(ao + 0x30)
                    print 'Real size of the attribute 0x{:0X}'.format(attr_real_size)
                    attr_length_2 = attr_real_size

                    # offset to datarun
                    offset_to_attribute = data.getWORD(ao + 0x20) 


                    print 'data runs...'
                    s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - (2 * attr_name_length + 0x40))
                    for k in s:
                        print '0x{:02x}'.format(k),

                    print ''

                    data_runs = self._decode_data_runs(s)

                    for data_run in data_runs:
                        n, lcn = data_run

                        file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                        size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                        print '0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes)


                if std_attr_type == 0xA0:
                    # $INDEX_ALLOCATION
                    # sa zicem ca datarun-ul a fost citit, mai sus in atribut

                    for data_run in data_runs:
                        n, lcn = data_run

                        file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                        size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                        print 'INDX 0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes)

                        ofs = file_offset

                        indx_magic = data.getStream(ofs, ofs + 4)
                        print 'Magic: {}'.format(indx_magic)

                        if indx_magic != 'INDX':
                            break

                        vcn_idx_record = data.getQWORD(ofs + 16)
                        print 'VCN of this Index record in the Index Allocation: 0x{:0x}'.format(vcn_idx_record)

                        ofs_first_index_entry = data.getDWORD(ofs + 0x18 + 0x00)
                        total_size_of_index_entries = data.getDWORD(ofs + 0x18 + 0x04)

                        print 'Offset to first index entry: 0x{:0X}'.format(ofs_first_index_entry)
                        print 'Total size of index entries: 0x{:0X}'.format(total_size_of_index_entries)
                        size_update_seq = data.getWORD(ofs + 6)
                        print 'Size in words of  Update Sequence: 0x{:0X}'.format(size_update_seq)
                        #sys.exit()

                        non_leaf_node = data.getBYTE(ofs + 0x18 + 0x0c)
                        print 'Non-leaf node Flag (has sub-nodes): {}'.format(non_leaf_node)

                        #sys.exit()
                        #off = ofs + 0x58 # FIXME! calculat #0x2a + size_update_seq*2 - 2

                        # ofs_first_index_entry is relative to 0x18 (documentation says this)
                        off = ofs + ofs_first_index_entry + 0x18

                        if attr_name == '$I30':
                            # we support only this kind of index

                            while 1:
                                # index entry sau index record header
                                # FIXME! we do not handle subnodes
     
                                ie_file_reference = data.getQWORD(off + 0)
                                print 'File reference: 0x{:0X}'.format(ie_file_reference)

                                length_index_entry = data.getWORD(off + 8)
                                print 'Length of the index entry: 0x{:0X}'.format(length_index_entry)

                                offset_to_filename = data.getWORD(off + 0x0a)
                                print 'Offset to filename: 0x{:0X}'.format(offset_to_filename)

                                # in documentation, this seems to be fixed offset
                                # however, this field seems to be wrong, because it's not always equal to 0x52 ...???
                                offset_to_filename = 0x52

                                index_flags = data.getWORD(off + 0x0c)
                                print 'Index flags: 0x{:0X}'.format(index_flags)

                                length_of_filename = data.getBYTE(off + 0x50)
                                print 'Length of the filename: 0x{:0X}'.format(length_of_filename)

                                ie_filename = data.getStream(off + offset_to_filename, off + offset_to_filename + length_of_filename*2)
                                print 'Filename: {}'.format(self._widechar_to_ascii(ie_filename))

                                if index_flags & 1:
                                    vcn_subnodes = data.getQWORD(off + 2 * length_of_filename + 0x52)
                                    print 'VCN of index buffer with sub-nodes: 0x{:0X}'.format(vcn_subnodes)

                                off += length_index_entry

                                print ''

                                if index_flags & 2: #or length_index_entry == 0x260:
                                    break
                        else:
                            print 'We support only $I30 index !'

                        #sys.exit()

                if std_attr_type == 0x30:
                    # $FILE_NAME
                    allocated_size_of_file = data.getQWORD(ao + offset_to_attribute + 0x28)
                    print 'Allocated size of file: 0x{:0X}'.format(allocated_size_of_file)

                    real_size_of_file = data.getQWORD(ao + offset_to_attribute + 0x30)
                    print 'Real size of file: 0x{:0X}'.format(real_size_of_file)

                    attr_flags = data.getDWORD(ao + offset_to_attribute + 0x38)
                    print 'Flags: 0x{:0X}'.format(attr_flags)

                    filename_length = data.getBYTE(ao + offset_to_attribute + 0x40)
                    attr_filename = data.getStream(ao + offset_to_attribute + 0x42, ao + offset_to_attribute + 0x42 + filename_length * 2)
                    attr_filename = ''.join([chr(c) for c in attr_filename if c != 0])
                    print 'File name: {0}'.format(attr_filename)

                if std_attr_type == 0x90:
                    # $INDEX_ROOT
                    ofs = ao + offset_to_attribute

                    # index root attr
                    bytes_per_index_record = data.getDWORD(ofs + 8)
                    print 'Bytes per Index Record: 0x{:0X}'.format(bytes_per_index_record)

                    clusters_per_index_record = data.getBYTE(ofs + 12)
                    print 'Clusters per Index Record: 0x{:0X}'.format(clusters_per_index_record)


                    print '-= index node header =-'
                    # index node header
                    ofs_first_index_entry = data.getDWORD(ofs + 16 + 0)
                    print 'Offset to first index entry: 0x{:0X}'.format(ofs_first_index_entry)

                    total_size_of_index_entries = data.getDWORD(ofs + 16 + 4)
                    print 'Total size of index entries: 0x{:0X}'.format(total_size_of_index_entries)

                    index_flags = data.getBYTE(ofs + 16 + 0x0c)
                    print 'Large index (index allocation needed): {}'.format(index_flags)

                    off = ofs + 16 + 16
                    if attr_name == '$I30':
                        # we support only this kind of index

                        while 1:
                            print '\n-= index entry =-'

                            # index entry
                            ie_file_reference = data.getQWORD(off + 0)
                            print 'File reference: 0x{:0X}'.format(ie_file_reference)

                            length_index_entry = data.getWORD(off + 8)
                            print 'Length of the index entry: 0x{:0X}'.format(length_index_entry)

                            length_stream = data.getWORD(off + 10)
                            print 'Length of the stream: 0x{:0X}'.format(length_stream)

                            ie_flags = data.getBYTE(off + 12)
                            print 'Flag: 0x{:0X}'.format(ie_flags)

                            if ie_flags & 1:
                                ie_vcn = data.getQWORD(off + length_index_entry - 8)
                                print 'Last index entry, VCN of the sub-node in the Index Allocation: 0x{:0X}'.format(ie_vcn)
                                """
                                x = off + 16
                                ie_stream = data.getStream(x, x + length_stream)
                                print ie_stream
                                """

                            if ie_flags & 2:
                                break


                            length_of_filename = data.getBYTE(off + 0x50)
                            print 'Length of the filename: 0x{:0X}'.format(length_of_filename)

                            offset_to_filename = 0x52
                            ie_filename = data.getStream(off + offset_to_filename, off + offset_to_filename + length_of_filename*2)
                            print 'Filename: {}'.format(self._widechar_to_ascii(ie_filename))

                            off += length_index_entry 




                if std_attr_type == 0x80:
                    # $DATA
                    attr_data = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length_2)
                    #print attr_data

                ao += attr_length
                print '-----'

            print ''

            attr_type = self.dataModel.getDWORD(file_record + off_first_attr)

            #print hex(attr_type)

            self._viewMode.selector.addSelection((start_mft + i*self.file_record_size, start_mft + i*self.file_record_size + self.file_record_size, QtGui.QBrush(QtGui.QColor(125, 175, 150)), 0.3), type=TextSelection.SelectionType.IF_CURSOR_IN_RANGE)
        return n_file_records


    def _widechar_to_ascii(self, s):
        return ''.join([chr(c) for c in s if c != 0])

    def _get_mft_data_runs(self):
        start_mft = self.lcn_of_mft * self.sectors_per_cluster * self.bytes_per_sector
        file_record_size = 1024 #!FIXME #self.clusters_per_mft_record * self.sectors_per_cluster * self.bytes_per_sector

        print ''
        print '=====================     GET $MFT DATA RUNS     ====================='

        i = 0

        print 'FILE_RECORD #{0}'.format(i)

        file_record = start_mft + i*file_record_size
        fr = file_record
        off_first_attr = self.dataModel.getWORD(file_record+0x14)
        data = self.dataModel

        real_size = data.getDWORD(fr + 0x18)
        print 'Real size of file record: 0x{:1X}'.format(real_size)

        allocated_size = data.getDWORD(fr + 0x1c)
        print 'Allocated size of file record: 0x{:0X}'.format(allocated_size)

        file_reference = data.getQWORD(fr + 0x20)
        print 'File reference to the base FILE record: 0x{:0X}'.format(file_reference)

        next_attribute_id = data.getWORD(fr + 0x28)
        print 'Next Attribute Id: 0x{:0X}'.format(next_attribute_id)

        ao = fr + off_first_attr 
        while 1:
            std_attr_type = data.getDWORD(ao + 0x00)
            if std_attr_type == 0xFFFFFFFF:
                break

            attrs = {0x10 : "$STANDARD_INFORMATION", 0x30: "$FILE_NAME", 0x80: "$DATA", 0xB0: "$BITMAP", 0x60: "$VOLUME_NAME", 0x70: "$VOLUME_INFORMATION",
                     0x50 : "$SECURITY_DESCRIPTOR", 0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION", 0x100: "$LOGGED_UTILITY_STREAM"}

            # standard attribute header
            print 'Attribute type: {0}'.format(attrs[std_attr_type])

            attr_length = data.getDWORD(ao + 0x04)
            print 'Length: 0x{:0X}'.format(attr_length)

            non_resident_flag = data.getBYTE(ao + 0x08)
            print 'Non-resident flag: 0x{:0X}'.format(non_resident_flag)

            attr_name_length = data.getBYTE(ao + 0x09)
            print 'Name length: 0x{:0X}'.format(attr_name_length)

            c_start = ao
            c_end = ao + attr_length

            if non_resident_flag and not attr_name_length and std_attr_type == 0x80:
                # $DATA
                starting_vcn = data.getQWORD(ao + 0x10)
                print 'Starting VCN 0x{:0X}'.format(starting_vcn)

                last_vcn = data.getQWORD(ao + 0x18)
                print 'Last VCN 0x{:0X}'.format(last_vcn)

                attr_real_size = data.getQWORD(ao + 0x30)
                print 'Real size of the attribute 0x{:0X}'.format(attr_real_size)
                attr_length_2 = attr_real_size

                # offset to datarun
                offset_to_attribute = data.getWORD(ao + 0x20) 

                print 'data runs...'
                s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - 0x40)
                for k in s:
                    print '0x{:02x}'.format(k),

                print ''

                data_runs = self._decode_data_runs(s)

                for data_run in data_runs:
                    n, lcn = data_run

                    file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                    size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                    print '0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes)

                return data_runs

            ao += attr_length
            print '-----'


    def _sign_extend(self, value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    def _get_le(self, s):
        n = 0x00

        for x in s[::-1]:
            n = n << 8
            n = n | x

        n = self._sign_extend(n, len(s) * 8)
        #print len(s)
        """
        n = n & 0xFFFF
        if x & 0x80:
            # last byte is signed
            n = n ^ 0xFFFF
            n = n - 1
            n = -n
        """

        return n


    def _decode_data_runs(self, stream):
        s = stream
        result = []

        prev_lcn_start = 0
        while 1:
            #print '0x{:02x}'.format(k),
            k = s[0]

            if k == 0x00:
                break

            length_size = k & 0x0F
            offset_size = (k & 0xF0) >> 4

            if offset_size == 0x00:
                # sparse file
                # !FIXME, should we do something with it?
                break

            n_clusters = self._get_le(s[1:1 + length_size])
            rel_lcn_start  = self._get_le(s[1 + length_size: 1 + length_size + offset_size])

            print 'LCN start RELATIVE 0x{:04x}'.format(rel_lcn_start)

            lcn_start  = prev_lcn_start + rel_lcn_start

            print 'length size 0x{:0x}'.format(length_size)
            print 'offset size 0x{:0x}'.format(offset_size)

            print 'number of clusters 0x{:04x}'.format(n_clusters)
            print 'LCN start 0x{:04x}'.format(lcn_start)

            print ''

            s = s[1 + length_size + offset_size:]

            result += [(n_clusters, lcn_start)]
            prev_lcn_start = lcn_start

        return result

    def hintDisasm(self):
        return DisasmViewMode.Disasm_x86_16bit

    def hintDisasmVA(self, offset):
        return offset

    def disasmVAtoFA(self, va):
        return va
        
    def getBanners(self):
        return [Banners.FileAddrBanner(self.dataModel, self._viewMode), Banners.TopBanner(self.dataModel, self._viewMode), Banners.BottomBanner(self.dataModel, self._viewMode)]

    def registerShortcuts(self, parent):
        self._parent = parent
        self.w = DialogGoto(parent, self)
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._showit, self._showit)]
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("s"), parent, self.skip_chars, self.skip_chars)]
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("e"), parent, self.skip_block, self.skip_block)]

        # goto $MFT
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+M"), parent, self._goto_mft, self._goto_mft)]


    def _goto_mft(self):
        self._viewMode.goTo(self.lcn_of_mft * self.sectors_per_cluster * self.bytes_per_sector)


    def _showit(self):
        if not self.w.isVisible():
            self.w.show()
        else:
            self.w.hide()

    def skip_block(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        import string

        x = string.find(self.dataModel.getData(), '\x00'*8, off)
        if x == -1:
            x = off


        if x == off:
            if x < sizeOfData - 1:
                x += 1

        self._viewMode.goTo(x)

        return

    def skip_chars(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off + 1

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        # skip bytes of current value
#        import time

        BYTES = 512
#        k = time.time()
        b = self.dataModel.getStream(off, off + 1)
        z = b * BYTES

        # compare stream of bytes
        z = self.dataModel.getStream(off, off+BYTES)
        while x < sizeOfData - BYTES and self.dataModel.getStream(x, x + BYTES) == z:
            x += BYTES

        while x < sizeOfData - 1 and self.dataModel.getBYTE(x) == ord(b):
            x += 1

#        print time.time() - k

        self._viewMode.goTo(x)
