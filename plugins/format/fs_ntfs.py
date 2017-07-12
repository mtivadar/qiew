import logging

import DataModel

class NtfsError(Exception):
    def __init__(self, message):
        super(NtfsError, self).__init__(message)

class Helper(object):
    @staticmethod
    def _widechar_to_ascii(s):
        return ''.join([chr(c) for c in s if c != 0])

    @staticmethod
    def logger():
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        return logger

    @staticmethod
    def _fixup_seq_numbers(data, update_seq_array, size_update_seq, update_seq, bytes_per_sector):
        log = Helper.logger()

        size_in_bytes = data.getDataSize()

        ## apply fixup
        k = 0
        i = 0

        fixup_array = DataModel.BufferDataModel(update_seq_array, 'fixup')

        while k < size_in_bytes:
            if i >= size_update_seq:
                break

            k += bytes_per_sector
            seq = data.getWORD(k - 2)

            fixup = fixup_array.getWORD(i * 2)

            log.debug('\tlast two bytes of sector: {:04x}, fixup {:04x}'.format(seq, fixup))

            if seq != update_seq:
                log.debug('\tupdate sequence check failed, image may be corrupt, continue anyway')


            fixup_s = fixup_array.getStream(i * 2, i * 2 + 2)
            data.getData()[k-2:k] = fixup_s
            i += 1


class AttrDefEntry(object):
    def __init__(self, a, t, f):
        self._a = a
        self._t = t
        self._f = f

    @property
    def name(self):
        return self._a

    @property
    def type(self):
        return self._t

    @property
    def flags(self):
        return self._f

class AttrDef(object):
    def __init__(self):
        self._Attrs = []
        self._Index = {}
        pass

    def add(self, attribute, _type, flags):
        obj = AttrDefEntry(attribute, _type, flags)
        self._Attrs += [obj]
        self._Index[_type] = obj

    def getByType(self, t):
        if t in self._Index:
            return self._Index[t]
        else:
            raise NtfsError('Attribute type 0x{:0x} not found in $AttrDef.'.format(t))

    def getAttributes(self):
        return self._Attrs

class AttributeStandardHeader(object):
    def __init__(self):
        pass
    
class Attribute_TYPES(object):
    def __init__(self, attr_type):
        self.attr_type = attr_type


    def postprocess(self):
        pass

class FileReference(object):
    def __init__(self, file_reference):
        self.record_number = file_reference & 0x0000FFFFFFFFFFFF
        self.seq_number = (file_reference & 0xFFFF) >> 48

class IndexHeader(object):
    def __init__(self):
        pass

class IndexEntry(object):
    def __init__(self):
        pass

class Attribute_INDEX_ALLOCATION(Attribute_TYPES):
    @classmethod
    def registered_for(cls, attr_type):
        return attr_type == 0xA0

    def __init__(self, attribute, file_record):
        # $INDEX_ALLOCATION

        self.entries = []
        self.attribute = attribute

        log = Helper.logger()

        return


        """
        for data_run in attribute.data_runs:
            
            # file data model
            data = attribute.data

            n, lcn = data_run

            bytes_per_cluster = file_record.sectors_per_cluster * file_record.bytes_per_sector
            file_offset = lcn * file_record.sectors_per_cluster * file_record.bytes_per_sector
            size_in_bytes = n * file_record.sectors_per_cluster * file_record.bytes_per_sector

            total_clusters_in_buffer = n

            log.debug('INDX: 0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))

            clusters = data.getStream(file_offset, file_offset + size_in_bytes)

            # buffered data model
            data = DataModel.BufferDataModel(clusters, 'lcn')

            # INDX structure at @file_offset
            #ofs = file_offset

            ofs = 0

            indx_magic = data.getStream(ofs, ofs + 4)
            Helper.logger().debug('Magic: {}'.format(indx_magic))

            if indx_magic != 'INDX':
                log.debug('Bad magic: {}, continue anyway with next data-run'.format(indx_magic))
                continue

            self.vcn_idx_record = data.getQWORD(ofs + 16)
            log.debug('VCN of this Index record in the Index Allocation: 0x{:0x}'.format(self.vcn_idx_record))

            self.ofs_first_index_entry = data.getDWORD(ofs + 0x18 + 0x00)
            self.total_size_of_index_entries = data.getDWORD(ofs + 0x18 + 0x04)

            log.debug('Offset to first index entry: 0x{:0X}'.format(self.ofs_first_index_entry))
            log.debug('Total size of index entries: 0x{:0X}'.format(self.total_size_of_index_entries))

            self.size_update_seq = data.getWORD(ofs + 6)
            log.debug('Size in words of Update Sequence: 0x{:0X}'.format(self.size_update_seq))

            self.update_seq = data.getWORD(ofs + 0x28)
            log.debug('Update Sequence number: 0x{:04x}'.format(self.update_seq))

            self.update_seq_array = data.getStream(ofs + 0x2a, ofs + 0x2a + self.size_update_seq * 2)

            g = 'Update Sequence: '
            for x in self.update_seq_array:
                g += '{:02x} '.format(x)
                
            log.debug('{}'.format(g))

            ## apply fixup
            k = 0
            i = 0

            fixup_array = DataModel.BufferDataModel(self.update_seq_array, 'fixup')

            while k < size_in_bytes:
                if i >= self.size_update_seq:
                    break

                k += file_record.bytes_per_sector
                seq = data.getWORD(k - 2)

                if seq != self.update_seq:
                    log.debug('update sequence check failed, image may be corrupt, continue anyway')

                
                fixup = fixup_array.getWORD(i * 2)

                log.debug('last two bytes of sector: {:04x}, fixup {:04x}'.format(seq, fixup))

                fixup_s = fixup_array.getStream(i * 2, i * 2 + 2)
                data.getData()[k-2:k] = fixup_s
                i += 1


            self.non_leaf_node = data.getBYTE(ofs + 0x18 + 0x0c)
            log.debug('Non-leaf node Flag (has sub-nodes): {}'.format(self.non_leaf_node))

            log.debug('')
            #sys.exit()
            #off = ofs + 0x58 # FIXME! calculat #0x2a + size_update_seq*2 - 2

            # ofs_first_index_entry is relative to 0x18 (documentation says this)
            off = ofs + self.ofs_first_index_entry + 0x18

            if attribute.std_header.name == '$I30':
                # we support only this kind of index

                log.debug('Iterating {} index...'.format(attribute.std_header.name))
                while 1:

                    entry = IndexEntry()

                    # index entry sau index record header
                    # FIXME! we do not handle subnodes

                    file_reference = data.getQWORD(off + 0)
                    log.debug('File reference: 0x{:0X}'.format(file_reference))
                    entry.file_reference = FileReference(file_reference)

                    entry.length_index_entry = data.getWORD(off + 8)
                    log.debug('Size of the index entry: 0x{:0X}'.format(entry.length_index_entry))

                    entry.offset_to_filename = data.getWORD(off + 0x0a)
                    log.debug('Offset to filename: 0x{:0X}'.format(entry.offset_to_filename))

                    # in documentation, this seems to be fixed offset
                    # however, this field seems to be wrong, because it's not always equal to 0x52 ...???
                    offset_to_filename = 0x52

                    entry.index_flags = data.getWORD(off + 0x0c)
                    log.debug('Index flags: 0x{:0X}'.format(entry.index_flags))

                    if entry.index_flags & 2:
                        _offset = off + total_clusters_in_buffer
                        vcn = _offset / bytes_per_cluster + 1

                        total_vcn = total_clusters_in_buffer
                        log.debug('Current VCN: {}'.format(vcn))
                        log.debug('Total VCNs: {}'.format(total_vcn))
                        log.debug('ofofset {}'.format(off))

                        if vcn < total_vcn:
                            off += 0x60#entry.length_index_entry
                            off = 0x10a8
                            continue
                        else:
                            break

                    entry.length_of_filename = data.getBYTE(off + 0x50)
                    log.debug('Length of the filename: 0x{:0X}'.format(entry.length_of_filename))

                    ie_filename = data.getStream(off + offset_to_filename, off + offset_to_filename + entry.length_of_filename*2)

                    ie_filename = Helper._widechar_to_ascii(ie_filename)
                    entry.filename = ie_filename
                    log.debug('Filename: {}'.format(entry.filename))

                    if entry.index_flags & 1:
                        entry.vcn_subnodes = data.getQWORD(off + 2 * entry.length_of_filename + 0x52)
                        log.debug('VCN of index buffer with sub-nodes: 0x{:0X}'.format(entry.vcn_subnodes))

                    off += entry.length_index_entry

                    log.debug('')

                    if entry.index_flags & 2:
                        break

                    self.entries.append(entry)
            else:
                log.debug("Index {} not supported.".format(attribute.std_header.name))
        log.debug('--=== end of index iteration ===--')
        log.debug('')

        """

class Attribute_INDEX_ROOT(Attribute_TYPES):
    @classmethod
    def registered_for(cls, attr_type):
        return attr_type == 0x90

    def _iterate_index_entries(self, data, off):
        log = Helper.logger()

        nodes = []
        entries = []
        while 1:
            log.debug('')
            log.debug('-= index entry =-')

            entry = IndexEntry()

            # index entry
            file_reference = data.getQWORD(off + 0)
            #print 'File reference: 0x{:0X}'.format(file_reference)
            entry.file_reference = FileReference(file_reference)

            entry.length_index_entry = data.getWORD(off + 8)
            #print 'Length of the index entry: 0x{:0X}'.format(entry.length_index_entry)

            entry.length_stream = data.getWORD(off + 10)
            #print 'Length of the stream: 0x{:0X}'.format(entry.length_stream)

            entry.index_flags = data.getBYTE(off + 12)
            log.debug('Index flags: 0x{:0X}'.format(entry.index_flags))

            if entry.index_flags & 1:
                entry.subnode_vcn = data.getQWORD(off + entry.length_index_entry - 8)
                log.debug('Last index entry, VCN of the sub-node in the Index Allocation: 0x{:0X}'.format(entry.subnode_vcn))
                nodes += [entry]

            if entry.index_flags & 2:
                # last index entry, exiting
                break


            entry.length_of_filename = data.getBYTE(off + 0x50)
            log.debug('Length of the filename: 0x{:0X}'.format(entry.length_of_filename))

            entry.offset_to_filename = data.getWORD(off + 0x0a)
            log.debug('Offset to filename: 0x{:0X}'.format(entry.offset_to_filename))

            # in documentation, this seems to be fixed offset
            # however, this field seems to be wrong, because it's not always equal to 0x52 ...???
            entry.offset_to_filename = 0x52

            # file name from index (ie_filenname)
            entry.filename = Helper._widechar_to_ascii( data.getStream(off + entry.offset_to_filename, off + entry.offset_to_filename + entry.length_of_filename*2) )
            log.debug('Filename: {}'.format(entry.filename))

            # add entry object
            entries.append(entry)
            off += entry.length_index_entry 

        return nodes, entries

    def _get_datarun_of_vcn(self, vcn, data_runs):

        k = 0
        for data_run in data_runs:
            
            # file data model from our attribute
            data = self.attribute.data

            n, lcn = data_run

            """
            vcn: 1
            clusters: 1a, 2b, 2c
            -> 2b, vcn_rel: 0
            """

            # vcn is in this data_run ?
            if k <= vcn < k+n:
                return data_run, vcn - k

            k += n

        return None


    def _fetch_vcn(self, vcn, data_run, datamodel):
        log = Helper.logger()
        file_record = self.file_record

        (n, lcn), rel_vcn = data_run

        log.debug('\t\tVCN relative to data-run: {}'.format(rel_vcn))

        bytes_per_cluster = file_record.sectors_per_cluster * file_record.bytes_per_sector
        file_offset       = (lcn + rel_vcn) * self.file_record.sectors_per_cluster * self.file_record.bytes_per_sector
        #size_in_bytes     = n * self.file_record.sectors_per_cluster * self.file_record.bytes_per_sector

        # only one vcn
        # is it possible to have more than one cluster/entry ? !TODO
        size_in_bytes     = 1 * self.file_record.sectors_per_cluster * self.file_record.bytes_per_sector

        clusters = datamodel.getStream(file_offset, file_offset + size_in_bytes)

        log.debug('\t\tINDX: 0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))

        # buffered data model
        data = DataModel.BufferDataModel(clusters, 'lcn')
        return data

    def _process_INDX(self, data, index_allocation_dataruns):
        log = Helper.logger()

        bytes_per_sector = self.file_record.bytes_per_sector

        ofs = 0

        indx_magic = data.getStream(ofs, ofs + 4)
        log.debug('Magic: {}'.format(indx_magic))

        if indx_magic != 'INDX':
            log.debug('Bad magic: {}, continue anyway with next data-run'.format(indx_magic))
            

        self.vcn_idx_record = data.getQWORD(ofs + 16)
        log.debug('VCN of this Index record in the Index Allocation: 0x{:0x}'.format(self.vcn_idx_record))

        self.ofs_first_index_entry = data.getDWORD(ofs + 0x18 + 0x00)
        self.total_size_of_index_entries = data.getDWORD(ofs + 0x18 + 0x04)

        log.debug('Offset to first index entry: 0x{:0X}'.format(self.ofs_first_index_entry))
        log.debug('Total size of index entries: 0x{:0X}'.format(self.total_size_of_index_entries))

        size_update_seq = data.getWORD(ofs + 6)
        log.debug('Size in words of Update Sequence: 0x{:0X}'.format(size_update_seq))

        update_seq = data.getWORD(ofs + 0x28)
        log.debug('Update Sequence number: 0x{:04x}'.format(update_seq))

        update_seq_array = data.getStream(ofs + 0x2a, ofs + 0x2a + size_update_seq * 2)

        g = 'Update Sequence: '
        for x in update_seq_array:
            g += '{:02x} '.format(x)
            
        log.debug('{}'.format(g))

        # fixup things
        Helper._fixup_seq_numbers(data, update_seq_array, size_update_seq, update_seq, self.file_record.bytes_per_sector)

        self.non_leaf_node = data.getBYTE(ofs + 0x18 + 0x0c)
        log.debug('Non-leaf node Flag (has sub-nodes): {}'.format(self.non_leaf_node))

        log.debug('')
        #sys.exit()
        #off = ofs + 0x58 # FIXME! calculat #0x2a + size_update_seq*2 - 2

        # ofs_first_index_entry is relative to 0x18 (documentation says this)
        off = ofs + self.ofs_first_index_entry + 0x18

        log.debug('Iterating {} index...'.format(self.attribute.std_header.name))

        nodes, entries = self._iterate_index_entries(data, off)
        if len(nodes) > 0:
            log.debug('!!! We have {} nodes !!!'.format(len(nodes)))

        for node in nodes:
            vcn = node.subnode_vcn
            data_run = self._get_datarun_of_vcn(vcn, index_allocation_dataruns)

            if data_run == None:
                log.debug('VCN {} not found in data-run, exiting.'.format(vcn))
                return

            newdata = self._fetch_vcn(vcn, data_run, self.attribute.data)
            log.debug('+++ process b-tree node, vcn: 0x{:x}. +++'.format(vcn))
            self._process_INDX(newdata, index_allocation_dataruns)

        # add entries
        self.entries.extend(entries)
        log.debug('')
        return nodes


    def postprocess(self):
        log = Helper.logger()

        # file data model from our attribute
        datamodel = self.attribute.data

        # check if we have sub-nodes from root
        if len(self.root_nodes) == 0:
            log.debug('Nothing to post-process.')
            return

        # check if we have $INDEX_ALLOCATION
        if '$INDEX_ALLOCATION' not in self.file_record.attributes_dict:
            log.debug('We do not have $INDEX_ALLOCATION attribute, exiting.')
            return

        index_allocation = self.file_record.attributes_dict['$INDEX_ALLOCATION']

        # check $I30
        if index_allocation.attribute.std_header.name != '$I30':
            log.debug('Index {} not supported yet.'.format(index_allocation.attribute.std_header.name))
            return

        # for debugging purpose
        for data_run in index_allocation.attribute.data_runs:
            
            n, lcn = data_run

            file_offset = lcn * self.file_record.sectors_per_cluster * self.file_record.bytes_per_sector
            size_in_bytes = n * self.file_record.sectors_per_cluster * self.file_record.bytes_per_sector

            total_clusters_in_buffer = n

            log.debug('INDX: 0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))


        for node in self.root_nodes:
            vcn = node.subnode_vcn
            log.debug('Need VCN: 0x{:0x}'.format(vcn))
            data_run = self._get_datarun_of_vcn(vcn, index_allocation.attribute.data_runs)

            if data_run == None:
                log.debug('VCN {} not found in data-run, exiting.'.format(vcn))
                return

            data = self._fetch_vcn(vcn, data_run, datamodel)

            # we should process INDX, recursively
            self._process_INDX(data, index_allocation.attribute.data_runs)


    def __init__(self, attribute, file_record):

        # $INDEX_ROOT

        self.file_record = file_record
        self.attribute = attribute

        data = attribute.data
        ao   = attribute.ao

        ofs = ao + attribute.std_header.offset_to_attribute

        log = Helper.logger()

        log.debug('Attribute: {} (0x{:X})'.format(attribute.std_header.attrdef.name, attribute.std_header.attrdef.type))

        # index root attr
        self.bytes_per_index_record = data.getDWORD(ofs + 8)
        log.debug('Bytes per Index Record: 0x{:0X}'.format(self.bytes_per_index_record))

        self.clusters_per_index_record = data.getBYTE(ofs + 12)
        log.debug('Clusters per Index Record: 0x{:0X}'.format(self.clusters_per_index_record))


        self.index_header = IndexHeader()
        log.debug('-= index node header =-')
        # index node header
        self.index_header.ofs_first_index_entry = data.getDWORD(ofs + 16 + 0)
        log.debug('Offset to first index entry: 0x{:0X}'.format(self.index_header.ofs_first_index_entry))

        self.index_header.total_size_of_index_entries = data.getDWORD(ofs + 16 + 4)
        log.debug('Total size of index entries: 0x{:0X}'.format(self.index_header.total_size_of_index_entries))

        self.index_header.index_flags = data.getBYTE(ofs + 16 + 0x0c)
        log.debug('Large index (index allocation needed): {}'.format(self.index_header.index_flags))

        self.entries = []

        off = ofs + 16 + 16
        self.root_nodes = []

        if attribute.std_header.name == '$I30':
            # we support only this kind of index

            nodes, entries = self._iterate_index_entries(data, off)
            self.entries.extend(entries)

            log.debug('We have {} sub-nodes:'.format(len(nodes)))

            for node in nodes:
                log.debug('sub-node with VCN: 0x{:x}'.format(node.subnode_vcn))

            self.root_nodes = nodes

        else:
            log.debug("Index {} not supported.".format(attribute.std_header.name))

        log.debug('')

class Attribute_DATA(Attribute_TYPES):
    @classmethod
    def registered_for(cls, attr_type):
        return attr_type == 0x80

    def __init__(self, attribute, file_record):
        log = Helper.logger()

        data = attribute.data
        ao   = attribute.ao

        self.attribute = attribute
        self.file_record = file_record

        if not attribute.std_header.non_resident_flag:
            # is resident

            ao = ao + attribute.std_header.offset_to_attribute
            
            self.blob = data.getStream(ao, ao + attribute.std_header.length)
            
            log.debug('data is contained in attribute, {} bytes.'.format(attribute.std_header.length))
            #log.debug(blob)

        if attribute.std_header.non_resident_flag:
            # is non resident, we have data runs

            for data_run in attribute.data_runs:
                n, lcn = data_run

                file_offset = lcn * file_record.sectors_per_cluster * file_record.bytes_per_sector
                size_in_bytes = n * file_record.sectors_per_cluster * file_record.bytes_per_sector

                log.debug('DATA: 0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))

        log.debug('')

    def get_data(self):

        attribute = self.attribute
        file_record = self.file_record
        dataModel = attribute.data

        blob = ''
        if attribute.std_header.non_resident_flag:
            for data_run in attribute.data_runs:
                n, lcn = data_run

                file_offset = lcn * file_record.sectors_per_cluster * file_record.bytes_per_sector
                
                # size in bytes is rounded-up to cluster size (could hide data)
                size_in_bytes = n * file_record.sectors_per_cluster * file_record.bytes_per_sector

                blob += dataModel.getStream(file_offset, file_offset + attribute.std_header.attr_real_size)

            self.blob = blob

        # if $data is resident, blob will be set in __init__
        return self.blob

class Attribute_STANDARD_INFORMATION(Attribute_TYPES):
    @classmethod
    def registered_for(cls, attr_type):
        return attr_type == 0x10

    def __init__(self, attribute, file_record):
        log = Helper.logger()
        log.debug('')

class Attribute_FILE_NAME(Attribute_TYPES):
    @classmethod
    def registered_for(cls, attr_type):
        return attr_type == 0x30

    def __init__(self, attribute, file_record):
        # $FILE_NAME

        log = Helper.logger()

        data = attribute.data
        ao   = attribute.ao

        self.allocated_size_of_file = data.getQWORD(ao + attribute.std_header.offset_to_attribute + 0x28)
        log.debug('Allocated size of file: 0x{:0X}'.format(self.allocated_size_of_file))

        self.real_size_of_file = data.getQWORD(ao + attribute.std_header.offset_to_attribute + 0x30)
        log.debug('Real size of file: 0x{:0X}'.format(self.real_size_of_file))

        self.attr_flags = data.getDWORD(ao + attribute.std_header.offset_to_attribute + 0x38)
        log.debug('Flags: 0x{:0X}'.format(self.attr_flags))

        self.filename_length = data.getBYTE(ao + attribute.std_header.offset_to_attribute + 0x40)

        filename_offset = ao + attribute.std_header.offset_to_attribute + 0x42
        attr_filename = data.getStream(filename_offset, filename_offset + self.filename_length * 2)

        self.attr_filename = Helper._widechar_to_ascii(attr_filename)
        log.debug('File name: {0}'.format(self.attr_filename))

        log.debug('')

class AttributeType(object):
    @staticmethod
    def recognize(attribute, file_record):

        attr_type = attribute.std_header.attrdef.type

        for cls in Attribute_TYPES.__subclasses__():
            if cls.registered_for(attr_type):
                return cls(attribute, file_record)


        return None

class Attribute(object):
    def __init__(self, dataModel, ao):
        self.data = dataModel
        self.ao = ao # stream offset
        self.std_header = AttributeStandardHeader()

class FileRecord(object):
    def __init__(self):
        self.attributes = []
        self.attributes_dict = {}

class MFT(object):
    def __init__(self, dataModel):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        self.dataModel = dataModel

        if self.dataModel.getDataSize() < 512:
            raise NtfsError("Invalid NTFS image")

        # compute $MFT cluster
        self.lcn_of_mft = self.dataModel.getQWORD(0x30)
        self.sectors_per_cluster = self.dataModel.getBYTE(0x0D)
        self.bytes_per_sector = self.dataModel.getWORD(0x0B)
        self.clusters_per_mft_record = self.dataModel.getDWORD(0x40)

        # file record
        start_mft = self.lcn_of_mft * self.sectors_per_cluster * self.bytes_per_sector

        # so, this is stored on dword, but it seems that only one byte it's considered
        self.clusters_per_mft_record = self._sign_extend(self.clusters_per_mft_record, 8)

        # it's computed like this        
        if self.clusters_per_mft_record < 0:
            self.file_record_size = 1 << -self.clusters_per_mft_record
        else:
            self.file_record_size = self.clusters_per_mft_record * self.sectors_per_cluster * self.bytes_per_sector    

        if start_mft > self.dataModel.getDataSize():
            raise NtfsError('MFT initialization failed.')
        else:
            # ok
            pass

    def _sign_extend(self, value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    def _get_mft_data_runs(self):
        log = self.logger

        start_mft = self.lcn_of_mft * self.sectors_per_cluster * self.bytes_per_sector
        file_record_size = self.file_record_size

        log.debug('')
        log.debug('=====================     GET $MFT DATA RUNS     =====================')

        i = 0

        log.debug('FILE_RECORD #{0}'.format(i))

        file_record = start_mft + i*file_record_size
        fr = file_record
        off_first_attr = self.dataModel.getWORD(file_record+0x14)


        data = self.dataModel

        real_size = data.getDWORD(fr + 0x18)
        log.debug('Real size of file record: 0x{:1X}'.format(real_size))

        allocated_size = data.getDWORD(fr + 0x1c)
        log.debug('Allocated size of file record: 0x{:0X}'.format(allocated_size))

        file_reference = data.getQWORD(fr + 0x20)
        log.debug('File reference to the base FILE record: 0x{:0X}'.format(file_reference))

        next_attribute_id = data.getWORD(fr + 0x28)
        log.debug('Next Attribute Id: 0x{:0X}'.format(next_attribute_id))

        ao = fr + off_first_attr 
        while 1:
            std_attr_type = data.getDWORD(ao + 0x00)
            if std_attr_type == 0xFFFFFFFF:
                # attribute list ends
                break

            attr_length = data.getDWORD(ao + 0x04)
            non_resident_flag = data.getBYTE(ao + 0x08)
            attr_name_length = data.getBYTE(ao + 0x09)

            if non_resident_flag and not attr_name_length and std_attr_type == 0x80:
                # $DATA
                starting_vcn = data.getQWORD(ao + 0x10)
                last_vcn = data.getQWORD(ao + 0x18)

                log.debug('Starting VCN: 0x{:0X}, last VCN: 0x{:0X}'.format(starting_vcn, last_vcn))

                attr_real_size = data.getQWORD(ao + 0x30)
                log.debug('Real size of the attribute: 0x{:0X}'.format(attr_real_size))
                attr_length_2 = attr_real_size

                # offset to datarun
                offset_to_attribute = data.getWORD(ao + 0x20) 

                log.debug('data runs...')
                s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - 0x40)

                _log = ''
                for k in s:
                    _log += '0x{:02x}'.format(k) + ' '
                    

                log.debug(_log)
                log.debug('')

                data_runs = self._decode_data_runs(s)

                for data_run in data_runs:
                    n, lcn = data_run

                    file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                    size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                    log.debug('0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))

                self.mft_data_runs = data_runs
                return data_runs

            ao += attr_length

            # not found
        return None


    def _datarun_of_file_record(self, which_file_record):

        # get data run of file_record
        for n, lcn in self.mft_data_runs:
            start_mft = lcn * self.sectors_per_cluster * self.bytes_per_sector
            mft_size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

            n_file_records = mft_size_in_bytes / self.file_record_size

            if which_file_record < n_file_records:
                return (n, lcn, which_file_record)
            else:
                which_file_record -= n_file_records

        return None


    def _widechar_to_ascii(self, s):
        return ''.join([chr(c) for c in s if c != 0])

    def _build_attrdef(self):
        datarun = self._datarun_of_file_record(4)
        if datarun is None:
            # file record not found
            raise NtfsError('Cannot find $AttrDef.')

        n, lcn, rel_record = datarun

        start_mft = lcn * self.sectors_per_cluster * self.bytes_per_sector
        mft_size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

        file_record = start_mft + 4*self.file_record_size

        log = self.logger

        off_first_attr = self.dataModel.getWORD(file_record+0x14)
        data = self.dataModel

        ao = file_record + off_first_attr

        _attrDef = AttrDef()

        # iterate attributes
        while 1:
            std_attr_type = data.getDWORD(ao + 0x00)
            if std_attr_type == 0xFFFFFFFF:
                break

            # standard attribute header
            attr_length = data.getDWORD(ao + 0x04)
            non_resident_flag = data.getBYTE(ao + 0x08)
            attr_name_length = data.getBYTE(ao + 0x09)

            if non_resident_flag and not attr_name_length and std_attr_type == 0x80:
                # $DATA

                # offset to datarun
                offset_to_attribute = data.getWORD(ao + 0x20) 

                # get dataruns of $AttrDef
                s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - 0x40)

                data_runs = self._decode_data_runs(s)

                for data_run in data_runs:
                    n, lcn = data_run

                    file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                    size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                    start = file_offset
                    while file_offset < file_offset + size_in_bytes:
                        label = data.getStream(start, start+0x80)
                        label = self._widechar_to_ascii(label)

                        tp = data.getDWORD(start + 0x80)

                        flags = data.getDWORD(start + 0x8c)

                        # last entry
                        if tp == 0x0:
                            break

                        _attrDef.add(label, tp, flags)

                        # next attrdef
                        start += 0xA0

            ao += attr_length

        log.debug('=====================     Dumping $AttrDef...     =====================')
        for a in _attrDef.getAttributes():
            log.debug('Attribute: {:30} type: 0x{:03X}, flags: 0x{:02X}'.format(a.name, a.type, a.flags))

        log.debug('')

        self.AttrDef = _attrDef
        return _attrDef

    def get_file_record(self, which_file_record):
        log = Helper.logger()

        log.debug('==================== [File record #{}] ===================='.format(which_file_record))

        datarun = self._datarun_of_file_record(which_file_record)
        if datarun is None:
            # file record not found
            return None

        n, lcn, rel_record = datarun

        start_mft         = lcn * self.sectors_per_cluster * self.bytes_per_sector
        mft_size_in_bytes =   n * self.sectors_per_cluster * self.bytes_per_sector

        file_record_offset = start_mft + rel_record*self.file_record_size

        # simple check
        fr = file_record_offset

        # get buffered data model
        data = DataModel.BufferDataModel(self.dataModel.getStream(fr, fr + self.file_record_size), 'file_record')
        fr = 0

        magic = data.getStream(fr + 0x00, fr + 0x04)
     
        if magic != "FILE":
            log.debug('magic does not mach "FILE", instead: {}.'.format(magic))
            return None
            #raise NtfsError('magic should mach "FILE", offset 0x{:x}'.format(fr))


        obj = FileRecord()

        offset_update_seq = data.getWORD(fr + 0x04)
        log.debug('Offset to update sequence: 0x{:0x}'.format(offset_update_seq))

        size_update_seq = data.getWORD(fr + 0x06)
        log.debug('Size in words of update sequence: 0x{:0x}'.format(size_update_seq))

        update_seq = data.getWORD(fr + offset_update_seq)
        log.debug('Update Sequence number: 0x{:04x}'.format(update_seq))

        # skip update seq number
        update_seq_array = data.getStream(fr + offset_update_seq + 2, fr + offset_update_seq + 2 + size_update_seq * 2)

        g = 'Update Sequence: '
        for x in update_seq_array:
            g += '{:02x} '.format(x)
            
        log.debug('{}'.format(g))

        # fixup things
        Helper._fixup_seq_numbers(data, update_seq_array, size_update_seq, update_seq, self.bytes_per_sector)


        off_first_attr = data.getWORD(fr + 0x14)

        flags = data.getWORD(fr + 0x16)
        log.debug('Flags: 0x{:0X}'.format(flags))

        real_size = data.getDWORD(fr + 0x18)
        log.debug('Real size of file record: 0x{:1X}'.format(real_size))

        allocated_size = data.getDWORD(fr + 0x1c)
        log.debug('Allocated size of file record: 0x{:0X}'.format(allocated_size))

        file_reference = data.getQWORD(fr + 0x20)
        log.debug('File reference to the base FILE record: 0x{:0X}'.format(file_reference))

        next_attribute_id = data.getWORD(fr + 0x28)
        log.debug('Next Attribute Id: 0x{:0X}'.format(next_attribute_id))

        log.debug('')

        obj.off_first_attr = off_first_attr
        obj.flags = flags
        obj.real_size = real_size
        obj.allocated_size = allocated_size
        obj.file_reference = file_reference
        obj.next_attribute_id = next_attribute_id

        #save fs geometry
        obj.sectors_per_cluster = self.sectors_per_cluster
        obj.bytes_per_sector = self.bytes_per_sector

        ao = fr + off_first_attr 

        log.debug('---=== attributes ===---')
        while 1:
            attribute = Attribute(self.dataModel, file_record_offset + ao)

            std_attr_type = data.getDWORD(ao + 0x00)
            if std_attr_type == 0xFFFFFFFF:
                break

            # standard attribute header
            log.debug('Attribute type: {0}'.format(self.AttrDef.getByType(std_attr_type).name))

            attr_length = data.getDWORD(ao + 0x04)
            log.debug('Length: 0x{:0X}'.format(attr_length))

            non_resident_flag = data.getBYTE(ao + 0x08)

            attr_name_length = data.getBYTE(ao + 0x09)

            log.debug('Non-resident flag: 0x{:0X}, name length: 0x{:0X}'.format(non_resident_flag, attr_name_length))

            # build instance

            attribute.std_header.type = std_attr_type
            attribute.std_header.attrdef = self.AttrDef.getByType(std_attr_type)
            attribute.std_header.length = attr_length
            attribute.std_header.non_resident_flag = non_resident_flag
            attribute.std_header.name_length = attr_name_length

            if not non_resident_flag and not attr_name_length:
                log.debug('Attribute is: {}'.format('resident, not named'))

                offset_to_attribute = data.getWORD(ao + 0x14)
                attr_length_2 = data.getDWORD(ao + 0x10)

                log.debug('Length of the attribute: 0x{:0X}'.format(attr_length_2))
                attr_name = ''

            if not non_resident_flag and  attr_name_length:
                log.debug('Attribute is: {}'.format('resident, named'))

                offset_to_attribute = data.getWORD(ao + 0x14)

                attr_name = data.getStream(ao + 0x18, ao + 0x18 + 2 * attr_name_length)
                attr_name = Helper._widechar_to_ascii(attr_name)

                log.debug('Attribute name: {0}'.format(attr_name))

                attr_length_2 = data.getDWORD(ao + 0x10)
                log.debug('Length of the attribute: 0x{:0X}'.format(attr_length_2))

            if non_resident_flag and not attr_name_length:

                log.debug('Attribute is: {}'.format('non resident, not named'))

                starting_vcn = data.getQWORD(ao + 0x10)
                last_vcn = data.getQWORD(ao + 0x18)
                log.debug('Starting VCN: 0x{:0X}, last VCN: 0x{:0X}'.format(starting_vcn, last_vcn))

                attr_real_size = data.getQWORD(ao + 0x30)
                log.debug('Real size of the attribute: 0x{:0X}'.format(attr_real_size))
                attr_length_2 = attr_real_size

                # offset to datarun
                offset_to_attribute = data.getWORD(ao + 0x20) 
                attr_name = ''

                attribute.std_header.starting_vcn = starting_vcn
                attribute.std_header.last_vcn = last_vcn
                attribute.std_header.attr_real_size = attr_real_size

                s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - 0x40)
                data_runs = self._decode_data_runs(s)

                attribute.data_runs = data_runs

                for data_run in data_runs:
                    n, lcn = data_run

                    file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                    size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                    log.debug('0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))




            if non_resident_flag and  attr_name_length:
                log.debug('Attribute is: {}'.format('non resident, named'))

                starting_vcn = data.getQWORD(ao + 0x10)
                last_vcn = data.getQWORD(ao + 0x18)
                log.debug('Starting VCN: 0x{:0X}, last VCN: 0x{:0X}'.format(starting_vcn, last_vcn))

                attr_name = data.getStream(ao + 0x40, ao + 0x40 + 2 * attr_name_length)
                attr_name = Helper._widechar_to_ascii(attr_name)
                
                log.debug('Attribute name: {0}'.format(attr_name))

                attr_real_size = data.getQWORD(ao + 0x30)
                log.debug('Real size of the attribute: 0x{:0X}'.format(attr_real_size))
                attr_length_2 = attr_real_size

                attribute.std_header.starting_vcn = starting_vcn
                attribute.std_header.last_vcn = last_vcn
                attribute.std_header.attr_real_size = attr_real_size

                # offset to datarun
                offset_to_attribute = data.getWORD(ao + 0x20) 

                s = data.getStream(ao + offset_to_attribute, ao + offset_to_attribute + attr_length - (2 * attr_name_length + 0x40))
                data_runs = self._decode_data_runs(s)

                attribute.data_runs = data_runs                

                for data_run in data_runs:
                    n, lcn = data_run

                    file_offset = lcn * self.sectors_per_cluster * self.bytes_per_sector
                    size_in_bytes = n * self.sectors_per_cluster * self.bytes_per_sector

                    log.debug('0x{:04x} clusters @ LCN 0x{:04x}, @ f_offset 0x{:x}, size_in_bytes {}'.format(n, lcn, file_offset, size_in_bytes))


            # populate std_header

            attribute.std_header.offset_to_attribute = offset_to_attribute
            attribute.std_header.length = attr_length_2
            attribute.std_header.name = attr_name

            ao += attr_length

            attribute.obj = AttributeType.recognize(attribute, obj)
            if attribute.obj is None:
                self.logger.debug('Attribute {} (0x{:x}) not supported yet.'.format(attribute.std_header.attrdef.name, attribute.std_header.attrdef.type))
                self.logger.debug('')

            obj.attributes.append(attribute)
            obj.attributes_dict[attribute.std_header.attrdef.name] = attribute.obj

        log.debug('---=== end attributes ===---')

        # postprocessing
        log.debug('postprocessing....')
        for attribute in obj.attributes:
            if attribute.obj:
                attribute.obj.postprocess()

        log.debug('')
        return obj


    def get_filerecord_of_path(self, path):
        # we accept windows path

        log = Helper().logger()

        path = path.split('\\')

        fileref = 5
        path = path
        for dr in path:
            log.debug('SUNTEM la {}'.format(dr))

            root = self.get_file_record(fileref)

            if '$INDEX_ROOT' in root.attributes_dict:
                entries = root.attributes_dict['$INDEX_ROOT'].entries
                for entry in entries:
                    log.debug('incerc_root ' + entry.filename)

                    if dr == entry.filename:
                        fileref = entry.file_reference.record_number
                        log.debug('merg ROOT pe asta 0x{:X}'.format(fileref))

            else:
                log.debug('YOU ARE FUCKED')
                break
                        

        root = self.get_file_record(fileref)
        if '$FILE_NAME' in root.attributes_dict:
            filename = root.attributes_dict['$FILE_NAME'].attr_filename

            if filename == dr:
                log.debug('file found.')
                return root
            else:
                log.debug('file not found.')
                return None
        else:
                return None
                

    def _get_le(self, s):
        n = 0x00

        for x in s[::-1]:
            n = n << 8
            n = n | x

        n = self._sign_extend(n, len(s) * 8)

        return n

    def _decode_data_runs(self, stream):
        log = self.logger

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

            lcn_start  = prev_lcn_start + rel_lcn_start

            """
            log.debug('...data runs...')

            q = ''
            for k in stream:
                q += '0x{:02x} '.format(k)

            log.debug(q)
            """

            log.debug('LCN relative 0x{:04x}, length_size: 0x{:x}, offset_size: 0x{:x}, n_clusters: 0x{:04x}, LCN start: 0x{:04x}'.format(rel_lcn_start, length_size, offset_size, n_clusters, lcn_start))

            s = s[1 + length_size + offset_size:]

            result += [(n_clusters, lcn_start)]
            prev_lcn_start = lcn_start

        log.debug('')

        return result


"""
todo:
   din ceva motiv, imaginea are anumiti bytes modificati !. se pare ca acei octeti pica in numele unor fisiere din index
        - am gasit de ce: fixups (update seq). inca nu e perfect rezolvat
        - fixed

   inca nu handleuim VCN sub-nodes la index entry! nu avem exemplu. 
        - avem acum, mai e ceva de lucru. nu primim sortat indexul.
        - fixed. nu e sortat perfect, da e ok

   in index_root poti sa ai intrari si sa si indice ca are subnodes !!!
   deci atentie la cautarea dupa fisier
         - aici e ciudatel putin. cred ca poti ori una ori alta.

   fixup la filerecord si la mft
         - trebuie vazut ....
         - fixed

    size of file ce il luam, nu e corect, este cel allocated.
         - fixed

"""