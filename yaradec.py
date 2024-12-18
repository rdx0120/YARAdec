import io
import struct
import sys
from collections import OrderedDict
from pathlib import Path
from typing import List
import re
import sys
from pathlib import Path

from yara_const import Opcode, StrFlag, RuleFlag, MetaType


def unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)


def unpack2(buf, idx, fmt):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[idx:idx + size])


class YaraRule(object):
    def __init__(self, data: dict):
        self.data = data
        self.data.setdefault('strings', OrderedDict())

    def __get_strings(self):
        for val in self.data.get('code', []):
            if val['opcode'] == Opcode.OP_PUSH and isinstance(val['args'][0], dict):
                self.data['strings'][val['args'][0]['identifier']] = val['args'][0]

    def get_rule(self):
        self.__get_strings()
        out = ''
        if self.data['flags'] & RuleFlag.PRIVATE:
            out += 'private '
        out += 'rule {ns}{identifier} {{\n'.format(**self.data)
        if self.data.get('metadata'):
            out += '\tmeta:\n'
            for name, val in self.data['metadata'].items():
                if val['type'] == MetaType.STRING:
                    value = '"{}"'.format(val['string'])
                elif val['type'] == MetaType.INTEGER:
                    value = '{}'.format(val['integer'])
                elif val['type'] == MetaType.BOOLEAN:
                    value = '{}'.format(val['boolean'])
                out += '\t\t{} = {}\n'.format(name, value)

        if self.data.get('strings'):
            out += '\tstrings:\n'
            for string in self.data['strings'].values():
                out += '\t\t{identifier}'.format(**string)

                if string['flags'] & StrFlag.HEXADECIMAL and string['flags'] & StrFlag.LITERAL:
                    out += ' = {str}'.format(**string)
                elif string['flags'] & StrFlag.LITERAL:
                    out += ' = "{str}"'.format(**string)
                else:
                    out += ' [__unrecoverable_with_yaradec__]'

                if string['flags'] & StrFlag.FULL_WORD:
                    out += ' fullword'
                # ASCII is the default
                # if string['flags'] & StrFlag.ASCII:
                #    out += ' ascii'
                if string['flags'] & StrFlag.WIDE:
                    out += ' wide'
                if string['flags'] & StrFlag.NO_CASE:
                    out += ' nocase'
                if string['flags'] & StrFlag.REGEXP:
                    out += ' regex'
                out += '\n'

        out += '\t__yaradec_asm__:\n'
        for val in self.data.get('code', []):
            out += '\t\t{}'.format(val['opcode'].name)
            if val['args']:
                out += ' ('
                for x in val['args']:
                    pass
                    if isinstance(x, int):
                        out += ' 0x{:X} '.format(x)
                    elif isinstance(x, dict):
                        out += ' {} '.format(x['identifier'])
                    else:
                        out += ' {} '.format(x)
                out += ')'
            out += '\n'
        out += '}\n'

        return out


class YaraDec_v11(object):
    def __init__(self, stream, size):
        self.stream = stream
        self.size = size
        self.data = io.BytesIO(stream.read(size))
        self.code = OrderedDict()

        if not self.relocate():
            raise RuntimeError('Invalid file')

        self.version, self.rules, self.externals, self.code_start, self.match, self.transition = unpack(self.data,
                                                                                                        '<L' + '4xL' * 5)

    def relocate(self):
        try:
            reloc = unpack(self.stream, '<L')[0]
            while reloc != 0xffffffff:
                if reloc > self.size - 4:
                    print("Invalid file (bad relocs)")
                    return False

                reloc_target = struct.unpack('<L', self.data.getbuffer()[reloc:reloc + 4])[0]
                if (reloc_target == 0xFFFABADA):
                    self.data.getbuffer()[reloc:reloc + 4] = b'\0\0\0\0'

                reloc = unpack(self.stream, '<L')[0]
        except struct.error:
            print("Invalid file (bad relocs)")
            return False
        return True

    def get_code(self, buf, ip):
        if self.code.get(ip):
            return []

        opcode = Opcode(unpack2(buf, ip, '<B')[0])
        args = []

        if opcode == Opcode.OP_HALT:
            next = []
        elif opcode in [
            Opcode.OP_CLEAR_M,
            Opcode.OP_ADD_M,
            Opcode.OP_INCR_M,
            Opcode.OP_PUSH_M,
            Opcode.OP_POP_M,
            Opcode.OP_SWAPUNDEF,
            Opcode.OP_INIT_RULE,
            Opcode.OP_PUSH_RULE,
            Opcode.OP_MATCH_RULE,
            Opcode.OP_OBJ_LOAD,
            Opcode.OP_OBJ_FIELD,
            Opcode.OP_CALL,
            Opcode.OP_IMPORT,
            Opcode.OP_INT_TO_DBL,
        ]:
            args.append(unpack2(buf, ip + 1, '<Q')[0])
            next = [ip + 8 + 1]
        elif opcode in [
            Opcode.OP_JNUNDEF,
            Opcode.OP_JLE,
            Opcode.OP_JTRUE,
            Opcode.OP_JFALSE,
        ]:
            next = [unpack2(buf, ip + 1, '<Q')[0], ip + 8]
        elif opcode == Opcode.OP_PUSH:
            arg = unpack2(buf, ip + 1, '<Q')[0]
            try:
                string = self.get_string(arg)
                if string:
                    args.append(string)
                else:
                    args.append(arg)
            except struct.error as exc:
                args.append(arg)
            next = [ip + 8 + 1]
        else:
            next = [ip + 1]

        data = dict(next=next, opcode=opcode, args=args)
        self.code[ip] = data
        return next

    def get_raw_str(self, addr):
        if not addr:
            return None
        return self.data.getvalue()[addr:].split(b'\0')[0].decode('utf-8')

    def get_meta(self, addr):
        fmt = '<L4xL4xL4xL4x'
        size = struct.calcsize(fmt)
        buf = self.data.getbuffer()
        i = 0
        metadatas = OrderedDict()

        while True:
            meta_data = unpack2(buf, addr + i * size, fmt)
            i += 1
            meta_type = MetaType(meta_data[0])
            if meta_type == MetaType.NULL:
                break
            data = dict(
                type=meta_type,
            )
            if meta_type == MetaType.STRING:
                data['string'] = self.get_raw_str(meta_data[3])
            elif meta_type == MetaType.INTEGER:
                data['integer'] = meta_data[1]
            elif meta_type == MetaType.BOOLEAN:
                data['boolean'] = bool(meta_data[1])
            metadatas[self.get_raw_str(meta_data[2])] = data
        return metadatas

    def get_ns(self, addr):
        fmt = '<' + 'L' * 32 + 'L'
        buf = self.data.getbuffer()
        ns = self.get_raw_str(unpack2(buf, addr, fmt)[32])
        return '{}:'.format(ns) if ns else ''

    def get_string(self, addr):
        buf = self.data.getbuffer()
        g_flags, length, identifier, str_data, chained_to = unpack2(buf, addr, '<LLL4xL4xL4x')

        flags = StrFlag(g_flags)

        if flags == StrFlag.NOFLAG or length > 0xffffff:
            return None

        str_str = unpack2(buf, str_data, '{}s'.format(length))[0]  # type: bytes

        data = dict(
            flags=flags,
            length=length,
            chained_to=chained_to,
            identifier=self.get_raw_str(identifier),
        )

        if flags & StrFlag.HEXADECIMAL and flags & StrFlag.LITERAL:
            data['str'] = '{' + ' '.join(['{:X}'.format(x) for x in str_str]) + '}'
        elif flags & StrFlag.LITERAL:
            data['str'] = str_str.decode('utf-8')
        else:
            data['str'] = None

        return data

    def get_rule(self, addr):
        fmt = '<L' + 'L' * 32 + '4xL4xL4xL4xL4xL'
        buf = self.data.getbuffer()
        rules_data = unpack2(buf, addr, fmt)

        data = dict()

        data['flags'] = RuleFlag(rules_data[0])

        identifier = rules_data[33]
        if identifier:
            data['identifier'] = self.get_raw_str(identifier)

        tags = rules_data[34]
        if tags:
            data['tags'] = self.get_raw_str(tags)

        meta = rules_data[35]
        if meta:
            data['metadata'] = self.get_meta(meta)

        ns = rules_data[37]
        if ns:
            data['ns'] = self.get_ns(ns)

        return data

    def parse_code(self):
        buf = self.data.getbuffer()
        ip = self.code_start

        todo = [ip]

        while todo:
            ip = todo.pop()
            todo += self.get_code(buf, ip)

    def get_rules(self):
        self.parse_code()
        rules = []
        cur_rule = None
        for val in self.code.values():
            if val['opcode'] == Opcode.OP_INIT_RULE:
                cur_rule = self.get_rule(val['args'][0])
                cur_rule['code'] = []
                rules.append(YaraRule(cur_rule))
            elif val['opcode'] == Opcode.OP_HALT:
                break
            cur_rule['code'].append(val)

        return rules


decoders = {
    11: YaraDec_v11,
    12: YaraDec_v11,  # TODO: look for changes in v12
}


def extract_strings_from_yarac(file_path):
    """
    Extract printable strings from a compiled YARA rule file (.yarac)
    
    Args:
        file_path (str): Path to the compiled YARA rule file
        
    Returns:
        list: List of extracted strings
    """
    try:
        # Read the binary file
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # Convert binary content to string, replacing non-printable chars
        text_content = content.decode('ascii', errors='ignore')
        
        # Regular expression for finding printable strings
        # Matches sequences of printable characters (length >= 4)
        string_pattern = re.compile(r'[\x20-\x7E]{4,}')
        
        # Extract all matches
        strings = string_pattern.findall(text_content)
        
        # Filter out common false positives and duplicates
        filtered_strings = []
        seen = set()
        
        for s in strings:
            # Skip if we've seen this string before
            if s in seen:
                continue
                
            # Skip strings that are likely not relevant
            if any(skip in s.lower() for skip in ['http://', 'https://', '.dll', '.exe']):
                continue
                
            seen.add(s)
            filtered_strings.append(s)
            
        return filtered_strings
        
    except Exception as e:
        print(f"Error processing file: {e}", file=sys.stderr)
        return []

def process_yara_strings(strings):
    """
    Process and split YARA-related strings for better analysis
    
    Args:
        strings (list): List of extracted strings
        
    Returns:
        dict: Categorized strings
    """
    categories = {
        'yara_related': [],
        'potential_rules': [],
        'other_strings': []
    }
    
    for s in strings:
        # Check for YARA-specific content
        if 'YARA' in s or 'rule' in s.lower():
            categories['yara_related'].append(s)
            # Split if it contains multiple parts
            parts = re.split(r'[_\s]+', s)
            if len(parts) > 1:
                categories['yara_related'].extend(parts)
        
        # Check for potential rule names or identifiers
        elif re.match(r'^[A-Za-z][A-Za-z0-9_]*$', s):
            categories['potential_rules'].append(s)
        
        # Other strings that might be relevant
        else:
            categories['other_strings'].append(s)
    
    return categories

def main():
    if len(sys.argv) != 2:
        print("Usage: {} [path]".format(sys.argv[0]))
        sys.exit(1)
        
    yarac_path = sys.argv[1]
    path = Path(sys.argv[1])

    stream = path.open('rb')
    header, size, version = unpack(stream, '<4sLB')
    if header != b'YARA':
        print("Invalid file (bad header)")
        sys.exit(2)
    
    if not Path(yarac_path).exists():
        print(f"Error: File not found: {yarac_path}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Processing {yarac_path}...")
    
    # Extract strings
    extracted_strings = extract_strings_from_yarac(yarac_path)
    
    # Process and categorize strings
    categorized_strings = process_yara_strings(extracted_strings)
    
    # Print results
   
    for s in categorized_strings['yara_related']:
        print(f"- {s}")
        
    print("\n=== Rule Name ===")
    for s in categorized_strings['potential_rules']:
        print(f"- {s}")
        
    print("\n=== Decompiling the YARA rule ===")
    for s in categorized_strings['other_strings']:
        print(f"- {s}")
        


if __name__ == "__main__":
    main()
