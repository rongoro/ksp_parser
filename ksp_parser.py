#!/usr/bin/env python3

import argparse
import hashlib
import re
import subprocess
import sys

SECTION_RE = re.compile('\d+  \[.*?^_+$', re.MULTILINE | re.DOTALL)

class KSPParseException(Exception):
    pass

class KeySegment(object):
    FINGERPRINT_RE = re.compile('Key fingerprint = ([0-9A-F ]+)')
    KEYNUM_RE = re.compile('^(\d+)')
    FINGERPRINT_OK_RE = re.compile('\[(.?)\] Fingerprint OK')
    ID_OK_RE = re.compile('\[(.?)\] ID OK')

    def __init__(self, segment_text):
        self.segment_text = segment_text

    def __str__(self):
        return self.segment_text

    @property
    def keynum(self):
        return int(re.search(self.KEYNUM_RE, self.segment_text).groups()[0])

    @property
    def fingerprint(self):
        return re.search(self.FINGERPRINT_RE, self.segment_text).groups()[0]

    @property
    def fingerprint_ok(self):
        ok_value = re.search(self.FINGERPRINT_OK_RE, self.segment_text).groups()[0]
        return bool(ok_value.strip())

    @property
    def id_ok(self):
        ok_value = re.search(self.ID_OK_RE, self.segment_text).groups()[0]
        return bool(ok_value.strip())


class KSPFile(object):
    SHA256_SECTION_RE = re.compile("^SHA256 Checksum:(.*?)\[.?\]$", re.MULTILINE | re.DOTALL)
    RIPEMD160_SECTION_RE = re.compile("RIPEMD160 Checksum:(.*?)\[.?\]$", re.MULTILINE | re.DOTALL)

    def __init__(self, fileobject):
        self.fileobject = fileobject
        self.input_text = self.fileobject.read().decode()

    def _key_segments(self):
        segments = re.findall(SECTION_RE, self.input_text)

        return [KeySegment(segment) for segment in segments]

    @property
    def keys(self):
        return self._key_segments()

    @property
    def verified_keys(self):
        return [key for key in self.keys if key.id_ok and key.fingerprint_ok]

    @property
    def key_fingerprints(self):
        return [key.fingerprint for key in self.keys]

    @property
    def verified_key_fingerprints(self):
        return [key.fingerprint for key in self.verified_keys]

    @property
    def sha256_section(self):
        match = re.search(self.SHA256_SECTION_RE, self.input_text)
        return match.group()

    @property
    def ripemd160_section(self):
        match = re.search(self.RIPEMD160_SECTION_RE, self.input_text)
        return match.group()

    def _read_checksum(self, regex):
        match = re.search(regex, self.input_text)
        if len(match.groups()) != 1:
            return None
        h = ''.join(match.groups()[0].split())
        if not h.replace('_', ''):
            return None
        else:
            return h.upper()

    @property
    def read_sha256(self):
        return self._read_checksum(self.SHA256_SECTION_RE)

    @property
    def read_ripemd160(self):
        return self._read_checksum(self.RIPEMD160_SECTION_RE)

    def _calculate_hash(self, hashname):
        h = hashlib.new(hashname)
        self.fileobject.seek(0)
        h.update(self.fileobject.read())
        return h.hexdigest().upper()

    def calculate_sha256(self):
        return self._calculate_hash('sha256')

    def calculate_ripemd160(self):
        return self._calculate_hash('ripemd160')

    def file_checksums_ok(self, original_KSPFile):
        """Check that the file checksums match the given original file."""
        return ((self.read_sha256 == original_KSPFile.calculate_sha256()
                 and (self.read_ripemd160 == original_KSPFile.calculate_ripemd160())))

    def _fill_underscores(self, input_text, filler):
        output = []
        filler_index = 0
        for char in input_text:
            if char == '_':
                output.append(filler[filler_index])
                filler_index += 1
            else:
                output.append(char)
        return ''.join(output)

    def create_edited_file(self):
        if self.read_sha256 or self.read_ripemd160:
            raise KSPParseException("File has hashes, probable not an original file.")

        sha_match = re.search(self.SHA256_SECTION_RE, self.input_text)
        ripemd_match = re.search(self.RIPEMD160_SECTION_RE, self.input_text)

        output_text = [self.input_text[:sha_match.start()]]
        output_text.append(self._fill_underscores(
            self.sha256_section,
            self.calculate_sha256()))
        output_text.append('\n\n')
        output_text.append(self._fill_underscores(
            self.ripemd160_section,
            self.calculate_ripemd160()))
        output_text.append(self.input_text[ripemd_match.end():])
        return ''.join(output_text)

def prepare_file(args):
    ksp_original = KSPFile(args.original_file)
    output_text = ksp_original.create_edited_file()

    args.output_file.write(output_text.encode())

def verify_file(args):
    ksp_edited = KSPFile(args.edited_file)
    ksp_original = KSPFile(args.original_file)

    if ksp_edited.file_checksums_ok(ksp_original):
        print("File OK")
        return 0
    else:
        print("Checksums don't match")
        return -1

def print_ksp(args):
    ksp = KSPFile(args.edited_file)

    if args.verified and args.fingerprints:
        keys = ksp.verified_key_fingerprints
    elif args.verified:
        keys = ksp.verified_keys
    elif args.fingerprints:
        keys = ksp.key_fingerprints
    else:
        keys = ksp.keys

    for key in keys:
        print(key)

def fetch_verified(args):
    ksp = KSPFile(args.edited_file)

    gpg_args = ['gpg', '--recv-keys']
    gpg_args.extend(ksp.verified_key_fingerprints)

    return subprocess.run(gpg_args).returncode

def sign_verified(args):
    ksp = KSPFile(args.edited_file)

    gpg_args = ['gpg', '--sign-key']

    for key in ksp.verified_key_fingerprints:
        subprocess.run(gpg_args + [key])


def main():
    parser = argparse.ArgumentParser(description="""This tool parses KSP key party files and makes them easier to work with.

The general usage pattern looks like this:
 $ %(prog)s prepare ksp-file.txt ksp-file.txt.edit
 <go to party and edit ksp-file.txt.edit as appropriate>
 $ %(prog)s verify ksp-file.txt.edit ksp-file.txt
 <if it looks ok>
 $ %(prog)s print --verified ksp-file.txt.edit
 <make sure the list looks correct>
 $ %(prog)s fetch_verified ksp-file.txt.edit
 $ %(prog)s sign_verified ksp-file.txt.edit
    """, formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers()
    preparer_parser = subparsers.add_parser('prepare', help='Prepare a ksp file for editing. Produces a <FILE>.edit file')
    preparer_parser.add_argument('original_file', type=argparse.FileType('br'),
                                 help='The original ksp file')
    preparer_parser.add_argument('output_file', nargs='?', type=argparse.FileType('bw'),
                                 default=sys.stdout)
    preparer_parser.set_defaults(func=prepare_file)

    verifier_parser = subparsers.add_parser('verify', help='verify that an edit file comes from a given original file')
    verifier_parser.add_argument('edited_file', type=argparse.FileType('br'),
                        help='The ksp file edited during the signing party')
    verifier_parser.add_argument('original_file', type=argparse.FileType('br'),
                        help='The original ksp file')
    verifier_parser.set_defaults(func=verify_file)

    print_verified_parser = subparsers.add_parser('print', help='print key info')
    print_verified_parser.add_argument('--verified', action='store_true')
    print_verified_parser.add_argument('--fingerprints', action='store_true')
    print_verified_parser.add_argument('edited_file', type=argparse.FileType('br'),
                                       help='The ksp file edited during the signing party')
    print_verified_parser.set_defaults(func=print_ksp)

    fetch_verified_parser = subparsers.add_parser('fetch_verified', help='fetch the verified keys')
    fetch_verified_parser.add_argument('edited_file', type=argparse.FileType('br'),
                                       help='The ksp file edited during the signing party')
    fetch_verified_parser.set_defaults(func=fetch_verified)

    sign_verified_parser = subparsers.add_parser('sign_verified', help='sign the verified keys')
    sign_verified_parser.add_argument('edited_file', type=argparse.FileType('br'),
                                      help='The ksp file edited during the signing party')
    sign_verified_parser.set_defaults(func=sign_verified)

    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
