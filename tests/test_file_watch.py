"""Real filesystem coverage for the explicit, opt-in file observer."""
import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / 'operator_modules' / 'file_watch.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('test_file_watch_module', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FileWatchTests(unittest.TestCase):
    def test_opt_in_baseline_and_new_pdf(self):
        module = load_module()
        self.assertIsNotNone(module, 'file observation module is missing')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            (root / 'old.pdf').write_bytes(b'old content')
            watch = module.FileWatch(base / 'state')
            self.assertFalse(watch.status()['enabled'])
            watch.configure([root], consent=True)
            self.assertEqual(watch.scan_now()['events'], [])
            (root / 'new.pdf').write_bytes(b'new content')
            result = watch.scan_now()
            self.assertEqual([event['path'] for event in result['events']], [str(root / 'new.pdf')])
            self.assertEqual(result['events'][0]['proposal'], 'offer_summary')
            self.assertEqual(watch.scan_now()['events'], [])
            self.assertEqual((root / 'new.pdf').read_bytes(), b'new content')
    def test_filters_restart_and_pending_proposals(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            watch = module.FileWatch(base / 'state')
            watch.configure([root], consent=True, extensions=['.pdf', '.txt'])
            (root / 'report.PDF').write_bytes(b'not opened')
            (root / 'note.txt').write_text('not opened')
            (root / 'ignore.png').write_bytes(b'not opened')
            events = watch.scan_now()['events']
            self.assertEqual({Path(e['path']).name for e in events}, {'report.PDF', 'note.txt'})
            self.assertEqual([e['proposal'] for e in events if e['path'].endswith('.txt')], [None])
            resumed = module.FileWatch(base / 'state')
            self.assertEqual(resumed.scan_now()['events'], [])
            pending = resumed.status()['pending']
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['proposal'], 'offer_summary')
            resumed.acknowledge(pending[0]['id'])
            self.assertEqual(resumed.status()['pending'], [])
            resumed.disable(consent=True)
            self.assertFalse(module.FileWatch(base / 'state').status()['enabled'])
            with self.assertRaises(module.WatchError):
                resumed.scan_now()

    def test_refuses_missing_consent_and_hides_protected_symlinks(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            outside = base / 'outside'
            outside.mkdir()
            (outside / 'secret.pdf').write_bytes(b'secret')
            (root / 'link').symlink_to(outside, target_is_directory=True)
            (root / '.ssh').mkdir()
            watch = module.FileWatch(base / 'state')
            with self.assertRaises(module.WatchError):
                watch.configure([root])
            with self.assertRaises(module.WatchError):
                watch.configure([root / 'link'], consent=True)
            with self.assertRaises(module.WatchError):
                watch.configure([root / '.ssh'], consent=True)
            watch.configure([root], consent=True)
            (root / '.ssh' / 'secret.pdf').write_bytes(b'secret')
            (outside / 'new.pdf').write_bytes(b'secret')
            (root / '.env').write_text('secret')
            (root / 'visible.pdf').write_bytes(b'visible')
            self.assertEqual([e['path'] for e in watch.scan_now()['events']], [str(root / 'visible.pdf')])
            self.assertEqual((outside / 'new.pdf').read_bytes(), b'secret')

    def test_capacity_error_preserves_snapshot_and_permissions(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            watch = module.FileWatch(base / 'state')
            watch.configure([root], consent=True, max_entries=1)
            state = base / 'state' / 'state.json'
            previous = state.read_bytes()
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertEqual(state.parent.stat().st_mode & 0o777, 0o700)
            (root / 'one.pdf').write_bytes(b'1')
            (root / 'two.pdf').write_bytes(b'2')
            with self.assertRaises(module.WatchError):
                watch.scan_now()
            self.assertEqual(state.read_bytes(), previous)
            (root / 'two.pdf').unlink()
            self.assertEqual(len(watch.scan_now()['events']), 1)
    def test_pending_capacity_keeps_snapshot_until_acknowledged(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            watch = module.FileWatch(base / 'state')
            watch.configure([root], consent=True, max_entries=1)
            first = root / 'first.pdf'
            first.write_bytes(b'1')
            event = watch.scan_now()['events'][0]
            first.unlink()
            watch.scan_now()
            (root / 'second.pdf').write_bytes(b'2')
            with self.assertRaises(module.WatchError):
                watch.scan_now()
            watch.acknowledge(event['id'])
            self.assertEqual(Path(watch.scan_now()['events'][0]['path']).name, 'second.pdf')

    def test_depth_overflow_does_not_commit_partial_snapshot(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'selected'
            root.mkdir()
            watch = module.FileWatch(base / 'state')
            watch.configure([root], consent=True)
            old = (base / 'state' / 'state.json').read_bytes()
            deep = root
            for _ in range(40):
                deep = deep / 'd'
                deep.mkdir()
            with self.assertRaises(module.WatchError):
                watch.scan_now()
            self.assertEqual((base / 'state' / 'state.json').read_bytes(), old)


if __name__ == '__main__':
    unittest.main()
