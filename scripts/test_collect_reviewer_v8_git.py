"""Official release selection and archive member parsing."""
import unittest
import collect_reviewer_v8_git as g


class GitCollectionTests(unittest.TestCase):
    def test_distinct_stable_minor_releases_and_x64_portable_only(self):
        def release(tag,name,**kw):return dict(tag_name=tag,assets=[dict(name=name)],**kw)
        releases=[release('v2.56.0.windows.1','PortableGit-2.56.0-64-bit.7z.exe'),
                  release('v2.56.0.windows.2','PortableGit-2.56.0.2-64-bit.7z.exe'),
                  release('v2.55.0.windows.1','PortableGit-2.55.0-64-bit.7z.exe'),
                  release('v3.0.0.windows.1','PortableGit-3.0.0-64-bit.7z.exe',prerelease=True)]
        selected=g.choose_releases(releases,2)
        self.assertEqual([r['tag_name'] for r,_ in selected],['v2.56.0.windows.1','v2.55.0.windows.1'])

    def test_list_filters_folders_non_pe_and_oversize(self):
        text='Path = usr/bin/tool.exe\nSize = 100\nFolder = -\n\nPath = doc/file.txt\nSize = 50\n\nPath = lib\nSize = 0\nFolder = +\n\nPath = huge.dll\nSize = 17000000\n'
        self.assertEqual(g.listed_members(text),[('usr/bin/tool.exe',100)])

class GitCollectionWorkflowTests(unittest.TestCase):
    def test_download_digest_selection_and_seven_zip_only_execution(self):
        from argparse import Namespace
        import json
        from pathlib import Path
        import sys,tempfile,types
        from unittest.mock import patch
        from test_collect_reviewer_v8_fresh import pe
        asset_bytes=b'official archive fixture';new=pe(b'new');old=pe(b'old')
        release=dict(tag_name='v2.56.0.windows.1',html_url='https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.1',
            assets=[dict(name='PortableGit-2.56.0-64-bit.7z.exe',digest='sha256:'+g.c.sha(asset_bytes),
                         browser_download_url='https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.1/PortableGit.7z.exe')])
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        commands=[]
        def archive_reader(cmd,**kwargs):
            commands.append(cmd)
            if cmd[1]=='l':return types.SimpleNamespace(stdout=f'Path = usr/bin/new.exe\nSize = {len(new)}\n\nPath = usr/bin/old.exe\nSize = {len(old)}\n')
            return types.SimpleNamespace(stdout=new if cmd[-1].endswith('new.exe') else old)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();g.f.w.dump(bundle/'freeze-manifest.json',{})
            previous=root/'previous';g.f.w.dump(previous/'evaluation-manifest.json',dict(complete=True,
                freeze_manifest_sha256=g.f.t.digest(bundle/'freeze-manifest.json'),samples=[dict(sha256=g.c.sha(old))]))
            args=Namespace(bundle=bundle,previous=previous,output=root/'git',releases=2)
            with patch.dict(sys.modules,{'requests':types.SimpleNamespace(Session=Session)}),\
                 patch.object(g.shutil,'which',return_value='trusted-7z'),\
                 patch.object(g.subprocess,'run',side_effect=archive_reader),\
                 patch.object(g.f,'load_bundle',return_value=({}, {}, set())),\
                 patch.object(g.c,'download',side_effect=[json.dumps([release]).encode(),asset_bytes]),patch('builtins.print'):
                g.run(args)
            summary=g.f.read(args.output/'collection-summary.json')
            self.assertEqual(summary['unique_pe_count'],1);self.assertEqual(summary['overlap_count'],1)
            self.assertTrue(all(cmd[0]=='trusted-7z' for cmd in commands))
            self.assertEqual(len(g.f.read(args.output/'sources.json')),1)


if __name__=='__main__':unittest.main()
