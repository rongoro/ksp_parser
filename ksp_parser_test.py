
import io
import ksp_parser
import unittest

class KSPFileTest(unittest.TestCase):
    def setUp(self):
        self.originalfile = io.BytesIO(ORIGINAL_TEXT)
        self.editedfile = io.BytesIO(EDITED_TEXT)
        self.kspfile_original = ksp_parser.KSPFile(self.originalfile)
        self.kspfile_edited = ksp_parser.KSPFile(self.editedfile)

    def test_compare_original_vs_edited_file(self):
        self.assertEqual(self.kspfile_original.key_fingerprints,
                         self.kspfile_edited.key_fingerprints)
        self.assertFalse(self.kspfile_original.verified_key_fingerprints)

    def test_sha256_section(self):
        self.assertEqual("""SHA256 Checksum: 1A4D 5BF8   02C0 EB2F   81E8 01F9   BDF8 E489

                 036D B243   1ADB ADC7   9477 0F14   AE0E 6A1B              [ ]""",
                         self.kspfile_edited.sha256_section)

    def test_calculate_sha256(self):
        self.assertEqual("1A4D5BF802C0EB2F81E801F9BDF8E489036DB2431ADBADC794770F14AE0E6A1B",
                         self.kspfile_original.calculate_sha256())

    def test_calculate_ripemd160(self):
        self.assertEqual("1C9213C1E8569E3632F6496111FFF0DA5AB3F792",
                         self.kspfile_original.calculate_ripemd160())

    def test_read_sha256(self):
        self.assertEqual("1A4D5BF802C0EB2F81E801F9BDF8E489036DB2431ADBADC794770F14AE0E6A1B",
                         self.kspfile_edited.read_sha256)
        self.assertIsNone(self.kspfile_original.read_sha256)

    def test_read_ripemd160(self):
        self.assertEqual("1C9213C1E8569E3632F6496111FFF0DA5AB3F792",
                         self.kspfile_edited.read_ripemd160)
        self.assertIsNone(self.kspfile_original.read_ripemd160)

    def test_ripemd160_section(self):
        self.assertEqual("""RIPEMD160 Checksum: 1C92 13C1 E856 9E36 32F6    4961 11FF F0DA 5AB3 F792    [ ]""",
                         self.kspfile_edited.ripemd160_section)

    def test_check_file_checksums(self):
        self.assertTrue(self.kspfile_edited.file_checksums_ok(self.kspfile_original))

        self.assertFalse(self.kspfile_edited.file_checksums_ok(
            ksp_parser.KSPFile(io.BytesIO(b'FOO' + ORIGINAL_TEXT))))

    def test_keys(self):
        self.assertEqual(5, len(self.kspfile_edited.keys))

    def test_get_key_fingerprint(self):
        self.assertEqual('B8D4 EFF2 5588 DFDF 0000  1234 A2B1 0448 912B F510',
                         self.kspfile_edited.keys[0].fingerprint)

        self.assertEqual('FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA',
                         self.kspfile_edited.keys[2].fingerprint)

    def test_keynum(self):
        self.assertEqual(1, self.kspfile_edited.keys[0].keynum)
        self.assertEqual(5, self.kspfile_edited.keys[4].keynum)

    def test_fingerprint_ok(self):
        self.assertTrue(self.kspfile_edited.keys[2].fingerprint_ok)
        self.assertFalse(self.kspfile_edited.keys[1].fingerprint_ok)
        self.assertTrue(self.kspfile_edited.keys[3].fingerprint_ok)

    def test_id_ok(self):
        self.assertFalse(self.kspfile_edited.keys[1].id_ok)
        self.assertTrue(self.kspfile_edited.keys[2].id_ok)
        self.assertTrue(self.kspfile_edited.keys[3].id_ok)

    def test_verified_keys(self):
        self.assertEqual(2, len(self.kspfile_edited.verified_keys))
        self.assertEqual(['FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA',
                          'EEA4 CB62 5862 5BC3 CA7F  F344 E56C B333 5A7B EF89',],
                         [key.fingerprint for key in self.kspfile_edited.verified_keys])

    def test_verified_key_fingerprints(self):
        self.assertEqual(['FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA',
                          'EEA4 CB62 5862 5BC3 CA7F  F344 E56C B333 5A7B EF89',],
                         self.kspfile_edited.verified_key_fingerprints)

    def test_create_edited_text(self):
        self.assertRaises(ksp_parser.KSPParseException,
                          self.kspfile_edited.create_edited_file)

        self.assertEqual(PREPARED_TEXT,
                         self.kspfile_original.create_edited_file().encode())


class ParserCommandTest(unittest.TestCase):
    def test_prepare_file(self):
        pass


ORIGINAL_TEXT = b"""Friday, June 10, 2016;  10:15
                                                 Signing Wizard <wizard@sign.example.com>


         E X A M P L E   K E Y S I G N I N G   P A R T Y   # 1 

                     List of Participants  (v 1.0)


Here's what you have to do with this file:

(1) Print this UTF-8 encoded file to paper.

(2) Compute this file's SHA256 and RIPEMD160 checksums.

      gpg --print-md SHA256 ksp-file.txt
      gpg --print-md RIPEMD160 ksp-file.txt

(3) Fill in the hash values on the printout.

(4) Bring the printout, a pen, and proof of identity to the key signing party
    (and be on time!).


SHA256 Checksum: ____ ____   ____ ____   ____ ____   ____ ____

                 ____ ____   ____ ____   ____ ____   ____ ____              [ ]

RIPEMD160 Checksum: ____ ____ ____ ____ ____    ____ ____ ____ ____ ____    [ ]



001  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/AB5283DD 2013-12-08 [expires: 2021-03-23]
      Key fingerprint = B8D4 EFF2 5588 DFDF 0000  1234 A2B1 0448 912B F510
uid                  Alice Aaron <alice@aaron.example.com>
uid                  Alice Aaron <aaaron@eng.school.edu>

_______________________________________________________________________________

002  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/B6273DDF 2005-02-24 [expires: 2025-11-05]
      Key fingerprint = AA33 172C BAAA EE78 9562  A162 9833 2DDD BB15 6633
uid                  Bob Baron <bobbar@baron.example.org>
uid                  Bob Baron <baron@bar.on>
uid                  Bob Baron <bobbar@baron.example.com>
uid                  Bob Baron <bobbaron@common.example.com>

_______________________________________________________________________________

003  [ ] Fingerprint OK        [ ] ID OK
pub   2048R/BBAA4343 2017-05-22
      Key fingerprint = FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA
uid                  Carl Casper Carson <carl.carson@common.example.com>

_______________________________________________________________________________

004  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/FF447611 2005-04-01 [expires: 2018-05-08]
      Key fingerprint = EEA4 CB62 5862 5BC3 CA7F  F344 E56C B333 5A7B EF89
uid                  example.io/danadavids <danadavids@example.io>

_______________________________________________________________________________

005  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/CC388FDC 2017-04-22 [expires: 2019-12-03]
      Key fingerprint = 0997 7BEE A8FF C8CC E845  23CD 83FD FC87 23CD D822
uid                  Eve Earl <eveearl@common.example.com>

_______________________________________________________________________________
"""

PREPARED_TEXT = b"""Friday, June 10, 2016;  10:15
                                                 Signing Wizard <wizard@sign.example.com>


         E X A M P L E   K E Y S I G N I N G   P A R T Y   # 1 

                     List of Participants  (v 1.0)


Here's what you have to do with this file:

(1) Print this UTF-8 encoded file to paper.

(2) Compute this file's SHA256 and RIPEMD160 checksums.

      gpg --print-md SHA256 ksp-file.txt
      gpg --print-md RIPEMD160 ksp-file.txt

(3) Fill in the hash values on the printout.

(4) Bring the printout, a pen, and proof of identity to the key signing party
    (and be on time!).


SHA256 Checksum: 1A4D 5BF8   02C0 EB2F   81E8 01F9   BDF8 E489

                 036D B243   1ADB ADC7   9477 0F14   AE0E 6A1B              [ ]

RIPEMD160 Checksum: 1C92 13C1 E856 9E36 32F6    4961 11FF F0DA 5AB3 F792    [ ]



001  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/AB5283DD 2013-12-08 [expires: 2021-03-23]
      Key fingerprint = B8D4 EFF2 5588 DFDF 0000  1234 A2B1 0448 912B F510
uid                  Alice Aaron <alice@aaron.example.com>
uid                  Alice Aaron <aaaron@eng.school.edu>

_______________________________________________________________________________

002  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/B6273DDF 2005-02-24 [expires: 2025-11-05]
      Key fingerprint = AA33 172C BAAA EE78 9562  A162 9833 2DDD BB15 6633
uid                  Bob Baron <bobbar@baron.example.org>
uid                  Bob Baron <baron@bar.on>
uid                  Bob Baron <bobbar@baron.example.com>
uid                  Bob Baron <bobbaron@common.example.com>

_______________________________________________________________________________

003  [ ] Fingerprint OK        [ ] ID OK
pub   2048R/BBAA4343 2017-05-22
      Key fingerprint = FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA
uid                  Carl Casper Carson <carl.carson@common.example.com>

_______________________________________________________________________________

004  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/FF447611 2005-04-01 [expires: 2018-05-08]
      Key fingerprint = EEA4 CB62 5862 5BC3 CA7F  F344 E56C B333 5A7B EF89
uid                  example.io/danadavids <danadavids@example.io>

_______________________________________________________________________________

005  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/CC388FDC 2017-04-22 [expires: 2019-12-03]
      Key fingerprint = 0997 7BEE A8FF C8CC E845  23CD 83FD FC87 23CD D822
uid                  Eve Earl <eveearl@common.example.com>

_______________________________________________________________________________
"""

EDITED_TEXT = b"""Friday, June 10, 2016;  10:15
                                                 Signing Wizard <wizard@sign.example.com>


         E X A M P L E   K E Y S I G N I N G   P A R T Y   # 1 

                     List of Participants  (v 1.0)


Here's what you have to do with this file:

(1) Print this UTF-8 encoded file to paper.

(2) Compute this file's SHA256 and RIPEMD160 checksums.

      gpg --print-md SHA256 ksp-file.txt
      gpg --print-md RIPEMD160 ksp-file.txt

(3) Fill in the hash values on the printout.

(4) Bring the printout, a pen, and proof of identity to the key signing party
    (and be on time!).


SHA256 Checksum: 1A4D 5BF8   02C0 EB2F   81E8 01F9   BDF8 E489

                 036D B243   1ADB ADC7   9477 0F14   AE0E 6A1B              [ ]

RIPEMD160 Checksum: 1C92 13C1 E856 9E36 32F6    4961 11FF F0DA 5AB3 F792    [ ]



001  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/AB5283DD 2013-12-08 [expires: 2021-03-23]
      Key fingerprint = B8D4 EFF2 5588 DFDF 0000  1234 A2B1 0448 912B F510
uid                  Alice Aaron <alice@aaron.example.com>
uid                  Alice Aaron <aaaron@eng.school.edu>

_______________________________________________________________________________

002  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/B6273DDF 2005-02-24 [expires: 2025-11-05]
      Key fingerprint = AA33 172C BAAA EE78 9562  A162 9833 2DDD BB15 6633
uid                  Bob Baron <bobbar@baron.example.org>
uid                  Bob Baron <baron@bar.on>
uid                  Bob Baron <bobbar@baron.example.com>
uid                  Bob Baron <bobbaron@common.example.com>

_______________________________________________________________________________

003  [X] Fingerprint OK        [X] ID OK
pub   2048R/BBAA4343 2017-05-22
      Key fingerprint = FFCC 7766 3434 F35D BCA3  112C DB44 A6B3 FFE2 75BA
uid                  Carl Casper Carson <carl.carson@common.example.com>

_______________________________________________________________________________

004  [X] Fingerprint OK        [X] ID OK
pub   4096R/FF447611 2005-04-01 [expires: 2018-05-08]
      Key fingerprint = EEA4 CB62 5862 5BC3 CA7F  F344 E56C B333 5A7B EF89
uid                  example.io/danadavids <danadavids@example.io>

_______________________________________________________________________________

005  [ ] Fingerprint OK        [ ] ID OK
pub   4096R/CC388FDC 2017-04-22 [expires: 2019-12-03]
      Key fingerprint = 0997 7BEE A8FF C8CC E845  23CD 83FD FC87 23CD D822
uid                  Eve Earl <eveearl@common.example.com>

_______________________________________________________________________________
"""

if __name__ == "__main__":
    unittest.main()
