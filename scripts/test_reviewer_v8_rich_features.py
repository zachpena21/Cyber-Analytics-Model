#!/usr/bin/env python3
"""Synthetic PE and SHA-coverage checks; no dependencies or real samples required."""
import hashlib
import math
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace as NS
import unittest
import zipfile

import reviewer_v8_rich_features as r
import reviewer_v8_rich_feature_cache as c


def pe(plus=False, managed=False):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 134, 1)
    size = 240 if plus else 224
    struct.pack_into('<H', data, 148, size)
    opt = 152
    struct.pack_into('<H', data, opt, 0x20b if plus else 0x10b)
    struct.pack_into('<I', data, opt + 60, 512)
    directory, count = (112, 108) if plus else (96, 92)
    struct.pack_into('<I', data, opt + count, 16)
    table = opt + size
    data[table:table+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, table+8, 1024, 0x1000, 512, 512)
    struct.pack_into('<I', data, table+36, 0xa0000020)
    data[512:] = bytes(range(256)) * 2
    if managed:
        struct.pack_into('<II', data, opt+directory+14*8, 0x1000, 72)
        struct.pack_into('<I', data, 512, 72)
        struct.pack_into('<III', data, 520, 0x1080, 16, 0x2001b)
        data[640:644] = b'BSJB'
    return data


def values(data, libraries=''):
    feature = r.extract(bytes(data), libraries)
    c.validate_feature(feature)
    return dict(zip(r.FEATURE_NAMES, feature['values'])), feature['status']


class Features(unittest.TestCase):
    def test_empty_zip_member_preserves_payload(self):
        # pyzipper's older ZipInfo implementation indexes the final character.
        # Current stdlib versions may already handle the empty string safely.
        class LegacyInfo(zipfile.ZipInfo):
            def is_dir(self):
                return self.filename[-1] == '/'
        member = LegacyInfo('')
        with self.assertRaises(IndexError):
            member.is_dir()
        data = bytes(pe())
        archive = NS(infolist=lambda:[member], read=lambda entry,pwd:data)
        warnings = []
        found = list(c.archive_payloads(archive, None, warnings.append, 'fixture.zip'))
        self.assertEqual(found, [data])
        self.assertEqual(warnings[0]['error'], 'EmptyMemberName')

    def test_resume_allows_collector_fix_but_rejects_parser_or_input_changes(self):
        collector = str(Path(c.__file__))
        old = dict(input_sha256={collector:'old', 'parser.py':'same', 'cache.json':'same'},
                   feature_names=['a'], sample_sha256=['a'*64])
        new = dict(old, input_sha256={collector:'new', 'parser.py':'same', 'cache.json':'same'})
        c.verify_resume_identity(old,new)
        for path in ('parser.py', 'cache.json'):
            bad = dict(new, input_sha256=dict(new['input_sha256'], **{path:'changed'}))
            with self.assertRaisesRegex(ValueError, 'parser changed'):
                c.verify_resume_identity(old,bad)

    def test_sections_pe32_and_pe32plus(self):
        for plus in (False, True):
            actual, status = values(pe(plus))
            self.assertEqual(status, 'parsed')
            self.assertEqual(actual['section_entropy_max'], 8.)
            self.assertEqual(actual['section_exec_entropy_mean'], 8.)
            self.assertEqual(actual['section_virtual_excess_fraction'], .5)
            self.assertAlmostEqual(actual['section_max_log_virtual_raw_ratio'], math.log(3))
            self.assertEqual(actual['section_wx_count'], 1.)
            self.assertEqual(actual['section_raw_bytes_to_file_ratio'], .5)
            self.assertEqual(actual['clr_directory_present'], 0.)

    def test_clr_layout_and_flags(self):
        for plus in (False, True):
            actual, _ = values(pe(plus, True))
            for name in r.MANAGED_NAMES:
                expected = 16/1024 if name == 'clr_metadata_size_to_file_ratio' else 1.
                self.assertEqual(actual[name], expected, name)

    def test_clr_invalid_ranges_and_signature(self):
        data = pe(managed=True)
        data[640:644] = b'NOPE'
        actual, _ = values(data)
        self.assertEqual(actual['clr_header_readable'], 1.)
        self.assertEqual(actual['clr_metadata_signature_valid'], 0.)
        struct.pack_into('<II', data, 520, 0x11ff, 16)
        actual, _ = values(data)
        self.assertEqual(actual['clr_metadata_signature_valid'], 0.)
        struct.pack_into('<II', data, 152+96+14*8, 0x11ff, 72)
        actual, _ = values(data)
        self.assertEqual(actual['clr_directory_present'], 1.)
        self.assertEqual(actual['clr_header_readable'], 0.)

    def test_import_normalization(self):
        a = r.import_values('C:\\path\\PYTHON313.DLL VCRUNTIME140_1.DLL API-MS-WIN-CRT-stdio-l1-1-0.dll MSCOREE.DLL')
        b = r.import_values('python312.dll vcruntime140.dll api-ms-win-crt-stdio-l1-1-0.dll mscoree.dll')
        self.assertEqual(a, b)
        out = dict(zip(r.IMPORT_NAMES, a))
        for name in ('python-runtime.dll', 'vcruntime.dll', 'mscoree.dll'):
            self.assertEqual(out['ordinary_import='+name], 1.)
        self.assertEqual(out['ordinary_import_api_ms_crt'], 1.)
        self.assertEqual(sum(a), 4.)
        self.assertEqual(sum(r.import_values('python-helper.dll vcruntime-fake.dll')), 0.)

    def test_corrupt_headers_preserve_imports(self):
        for data in (b'', b'MZ', b'MZ'+b'\xff'*100, pe()[:200]):
            actual, status = values(data, 'mscoree.dll')
            self.assertEqual(status, 'invalid_pe_header')
            self.assertEqual(actual['pe_header_valid'], 0.)
            self.assertEqual(actual['ordinary_import=mscoree.dll'], 1.)
        data = pe()
        struct.pack_into('<H', data, 134, 65535)
        actual, status = values(data)
        self.assertEqual(status, 'invalid_section_table')
        self.assertEqual(actual['pe_header_valid'], 1.)

    def test_bounds_zero_raw_and_overlap(self):
        data = pe()
        table = 152+224
        struct.pack_into('<I', data, table+20, 900)
        actual, status = values(data)
        self.assertEqual(status, 'parsed_with_raw_bounds_errors')
        self.assertEqual(actual['section_raw_bounds_errors'], 1.)
        self.assertEqual(actual['section_raw_bytes_to_file_ratio'], 124/1024)
        struct.pack_into('<I', data, table+16, 0)
        actual, _ = values(data)
        self.assertEqual(actual['section_zero_raw_count'], 1.)
        self.assertEqual(actual['section_entropy_max'], 0.)
        data = pe()
        struct.pack_into('<H', data, 134, 2)
        data[table+40:table+80] = data[table:table+40]
        actual, _ = values(data)
        self.assertEqual(actual['section_raw_overlap_pairs'], 1.)
        self.assertEqual(actual['section_raw_bytes_to_file_ratio'], 1.)

    def test_required_sha_coverage_and_warning_tolerance(self):
        data = bytes(pe())
        sha = hashlib.sha256(data).hexdigest()
        other = 'a'*64
        entries = {sha:dict(libraries='mscoree.dll'), other:dict(libraries='')}
        def payloads(path, reader, on_error):
            on_error(dict(archive='unrelated.zip', member='bad'))
            yield data
            yield data
            yield b'MZ-unrequested'
        features, warnings = {}, []
        missing = c.collect([Path('fixture.zip')], entries, payloads, None, features, warnings, lambda:None)
        self.assertEqual(missing, {other})
        self.assertEqual(set(features), {sha})
        self.assertEqual(features[sha]['raw_sha256'], sha)
        self.assertEqual(len(warnings), 1)
        missing = c.collect([], {sha:entries[sha]}, payloads, None, features, warnings, lambda:None)
        self.assertEqual(missing, set())

    def test_file_signatures_and_input_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in [('sample.noextension', b'MZ'), ('wheel.whl', b'PK'), ('report.json', b'{}')]:
                (root/name).write_bytes(data)
            self.assertEqual({p.name for p in c.candidate_files([root, root])}, {'sample.noextension', 'wheel.whl'})
            path = root/'report.json'
            hashes = {str(path):c.digest(path)}
            c.verify_hashes(hashes)
            path.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'Input changed'):
                c.verify_hashes(hashes)

    def test_development_merge_replays_scores_and_preserves_group_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            freeze = root/'structural/freeze-manifest.json'
            c.dump(freeze, {})
            new_sha, old_sha = 'a'*64, 'b'*64
            names = ['baseline'+str(i) for i in range(66)]
            flags = ['flag'+str(i) for i in range(6)]
            row = dict(sha256=new_sha, label=1, source='wheel', adapter_probability=.9,
                       structural_primary_score=.4, structural_primary_prediction=0, structural_primary_routed=True,
                       bounded_comparison_score=.5, bounded_comparison_prediction=0, bounded_comparison_routed=True,
                       bounded_logit_correction=.1)
            evaluation = root/'evaluation'
            sample = dict(sha256=new_sha, label=1, source_id='wheel', byte_size=1024, input_location='sample.zip')
            c.dump(evaluation/'evaluation-manifest.json', dict(complete=True, threshold_tuning=False,
                     freeze_manifest_sha256=c.digest(freeze), samples=[sample]))
            c.dump(evaluation/'comparison-scores.json', [row])
            source = root/'samples.zip'
            source.write_bytes(b'PK synthetic metadata container')
            c.dump(root/'sources.json', [dict(path=str(source))])
            diagnostic_dir = root/'diagnostics'
            paths = [freeze, root/'sources.json', evaluation/'evaluation-manifest.json', evaluation/'comparison-scores.json']
            c.dump(diagnostic_dir/'diagnostic-inputs.json', dict(complete=True, threshold_tuning=False,
                     evaluation=str(evaluation), input_sha256={str(p):c.digest(p) for p in paths}))
            c.dump(diagnostic_dir/'feature-diagnostic-summary.json', dict(complete=True, sample_count=1))
            cache = dict(complete=True, feature_names=names+flags,
                         samples={new_sha:dict(vector=[0.]*72, libraries='')}, scores=[row])
            c.dump(diagnostic_dir/'feature-cache.json', cache)
            g = NS(load_inputs=lambda args:({old_sha:{}}, names, {}, []), ROUTE=.15,
                   exported_scores=lambda payload,X:[.4],
                   gated=lambda rows,scores,threshold:[int(score>=threshold) for score in scores],
                   checked_entry=lambda *args,**kwargs:None,
                   f=NS(t=NS(e=NS(IMPORT_FEATURES=flags, _import_values=lambda attrs:[0.]*6))))
            manifest = dict(models={name:dict(threshold=.6) for name in ('structural_primary', 'bounded_comparison')})
            v = NS(load_bundle=lambda path:(manifest, {}, {}, {}, {old_sha}),
                   PRIMARY='structural_primary', COMPARISON='bounded_comparison',
                   b=NS(exported_scores=lambda payload,X,rows:([.5],[.1])))
            def verify(a,b):
                if a != b:
                    raise ValueError('Score changed')
            diagnostic = NS(unique_records=lambda rows:{r['sha256']:r for r in rows}, verify_row=verify)
            provenance = {new_sha:dict(provenance=dict(package='numpy'))}
            audit = NS(provenance=lambda sources:provenance)
            args = NS(fresh_audit=[], fresh_comparison=[], structural_bundle=freeze.parent, diagnostics=diagnostic_dir)
            entries, _, hashes, converted, _, _ = c.load_development(args,g,v,diagnostic,audit)
            self.assertEqual(set(entries), {old_sha,new_sha})
            self.assertEqual(entries[new_sha]['provenance'], provenance[new_sha])
            self.assertEqual(converted, [new_sha])
            self.assertEqual(hashes[str(source)], c.digest(source))
            cache['samples'][new_sha]['vector'][66] = 1.
            c.dump(diagnostic_dir/'feature-cache.json', cache)
            with self.assertRaisesRegex(ValueError, 'features differ'):
                c.load_development(args,g,v,diagnostic,audit)
            cache['samples'][new_sha]['vector'][66] = 0.
            row['structural_primary_score'] = .41
            c.dump(evaluation/'comparison-scores.json', [row])
            marker = c.read(diagnostic_dir/'diagnostic-inputs.json')
            marker['input_sha256'][str(evaluation/'comparison-scores.json')] = c.digest(evaluation/'comparison-scores.json')
            c.dump(diagnostic_dir/'diagnostic-inputs.json', marker)
            c.dump(diagnostic_dir/'feature-cache.json', cache)
            with self.assertRaisesRegex(ValueError, 'score/gate parity failed'):
                c.load_development(args,g,v,diagnostic,audit)


if __name__ == '__main__':
    unittest.main()
