"""Unit tests for `storage_health.py` — block devices, mounts, backup footprint & pruning.

Dotąd jedynie `inspect_storage` raz wywołany w test_wave7 (happy-path). Tu każdą
funkcję testujemy jednostkowo na fałszywym `/sys/block`, `/proc/mounts` i katalogu
`.jarvis-mcp-backups` (świeży tmp per test; prawdziwy system plików niedotknięty).
"""
from __future__ import annotations

import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from tempfile import mkdtemp

sys.path.insert(0, ".")

import storage_health as sh  # noqa: E402


class StorageBase(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)

    def _blk(self, name: str, files: dict) -> Path:
        d = self.base / "sys" / "block" / name
        d.mkdir(parents=True)
        for rel, content in files.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(str(content), encoding="utf-8")
        return d

    def _mounts(self, lines: list[str]) -> Path:
        p = self.base / "mounts"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def _backup_file(self, project: Path, name: str, content: str, mtime: float | None = None) -> Path:
        bdir = project / ".jarvis-mcp-backups"
        bdir.mkdir(parents=True, exist_ok=True)
        p = bdir / name
        p.write_text(content, encoding="utf-8")
        if mtime is not None:
            os.utime(p, (mtime, mtime))
        return p


class InspectBlockDevicesTests(StorageBase):
    def test_drives_classified_with_media_model_temp_inflight(self):
        """nvme->NVMe, rotational=1->HDD, 0->SSD; model/temp/inflight zczytane."""
        self._blk("nvme0n1", {
            "size": 977105085,
            "device/model": "Samsung SSD 980 PRO 1TB",
            "device/hwmon/hwmon0/temp1_input": 40200,
            "inflight": "7 0",
        })
        self._blk("sda", {
            "size": 1953525168,
            "queue/rotational": 1,
            "device/model": "WDC WD40EFRX",
            "device/hwmon/hwmon1/temp1_input": 31000,
        })
        self._blk("sdb", {
            "size": 1000215216,
            "queue/rotational": 0,
            "device/name": "KIOXIA",   # model z pliku name gdy brak model
            "inflight": "garbage x",    # nie-digit czesci odfiltrowane
        })
        drives = sh.inspect_block_devices(self.base / "sys" / "block")
        self.assertEqual([d["device"] for d in drives], ["nvme0n1", "sda", "sdb"])
        self.assertEqual([d["media"] for d in drives], ["NVMe", "HDD", "SSD"])
        self.assertEqual(drives[0]["model"], "Samsung SSD 980 PRO 1TB")
        self.assertEqual(drives[0]["temp_c"], 40.2)
        self.assertEqual(drives[0]["inflight_io"], 7)
        self.assertEqual(drives[1]["model"], "WDC WD40EFRX")
        self.assertTrue(drives[1]["rotational"])
        self.assertEqual(drives[1]["temp_c"], 31.0)
        self.assertEqual(drives[1]["inflight_io"], 0)      # brak pliku inflight
        self.assertEqual(drives[2]["model"], "KIOXIA")
        self.assertIsNone(drives[2]["temp_c"])             # brak sensorow temp
        self.assertEqual(drives[0]["size_gb"], 465.9)      # 977105085*512B = 465.86 GB

    def test_virtual_prefixes_and_invalid_sizes_skipped(self):
        for vname in ("loop0", "ram0", "zram0", "dm-0", "sr0", "fd0"):
            self._blk(vname, {"size": "999999"})
        self._blk("sdx", {})                 # brak size -> pominiety
        self._blk("sdy", {"size": 0})        # size 0 -> pominiety
        self.assertEqual(sh.inspect_block_devices(self.base / "sys" / "block"), [])

    def test_drive_temp_range_filtering(self):
        self._blk("sda", {
            "size": 123,
            "device/hwmon/hwmon0/temp1_input": 116000,   # 116.0 > 115 -> odrzucony
            "device/hwmon/hwmon0/temp2_input": 42000,    # 42.0 -> pierwszy zacja
        })
        drives = sh.inspect_block_devices(self.base / "sys" / "block")
        self.assertEqual(drives[0]["temp_c"], 42.0)

    def test_sixteen_drive_cap(self):
        for i in range(20):
            self._blk(f"sd{i}", {"size": 1000})
        self.assertEqual(len(sh.inspect_block_devices(self.base / "sys" / "block")), 16)

    def test_missing_root_returns_empty(self):
        self.assertEqual(sh.inspect_block_devices(self.base / "nope"), [])


class InspectMountsTests(StorageBase):
    def test_watched_ro_detected_rw_and_foreign_ignored(self):
        p = self._mounts([
            "/dev/sdb1 /data ext4 ro,errors=remount-ro 0 0",   # ro -> alert
            "/dev/sdc1 /home ext4 rw,relatime 0 0",           # rw -> tylko checked
            "tmpfs /tmp tmpfs rw 0 0",                        # poza WATCHED
            "/dev/sdd1 /snap/core/x ext4 ro 0 0",             # prefix /snap/ pomijany
            "za krotka linia",
        ])
        res = sh.inspect_mounts(p)
        self.assertEqual(res["checked_mounts"], 2)             # /data + /home
        self.assertEqual(
            res["readonly_alerts"],
            [{"device": "/dev/sdb1", "mountpoint": "/data", "fstype": "ext4"}],
        )

    def test_all_flexible_opts_and_btrfs_zfs_watchlist(self):
        p = self._mounts([
            "/dev/vdb /mnt/a btrfs rw,noatime 0 0",
            "/dev/vdc /mnt/b zfs rw 0 0",
            "/dev/vdd /mnt/c ntfs3 ro 0 0",
            "/dev/vde /mnt/d exfat rw 0 0",
            "/dev/vdf /mnt/e f2fs ro 0 0",
        ])
        res = sh.inspect_mounts(p)
        self.assertEqual(res["checked_mounts"], 5)
        self.assertEqual({a["mountpoint"] for a in res["readonly_alerts"]}, {"/mnt/c", "/mnt/e"})

    def test_missing_file_zero_checked(self):
        res = sh.inspect_mounts(self.base / "nope")
        self.assertEqual(res, {"checked_mounts": 0, "readonly_alerts": []})


class BackupFootprintTests(StorageBase):
    def test_none_and_missing_dir_shapes(self):
        self.assertEqual(sh.backup_footprint(None), {"count": 0, "total_mb": 0.0})
        self.assertEqual(sh.backup_footprint(self.base / "proj"), {"count": 0, "total_mb": 0.0})

    def test_counts_only_bak_bytes(self):
        proj = self.base / "proj"
        self._backup_file(proj, "a.bak", "x" * (1024 * 1024))
        self._backup_file(proj, "b.bak", "y" * (512 * 1024))
        self._backup_file(proj, "notes.txt", "z" * (10 * 1024 * 1024))  # nie .bak
        (proj / ".jarvis-mcp-backups" / "podkatalog.bak").mkdir()        # katalog, nie plik
        res = sh.backup_footprint(proj)
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["total_mb"], 1.5)


class PruneMcpBackupsTests(StorageBase):
    def _make(self, count: int, mtime_start: float) -> Path:
        proj = self.base / "proj"
        for i in range(count):
            self._backup_file(proj, f"backup-{i:02d}.bak", "d" * (512 * 1024),
                              mtime=mtime_start + i * 100)
        return proj

    def test_noop_when_dir_missing(self):
        res = sh.prune_mcp_backups(self.base / "proj")
        self.assertEqual(res, {"ok": True, "removed": 0, "kept": 0, "freed_mb": 0.0})

    def test_keeps_five_newest_and_removes_older(self):
        """keep_latest poniżej 5 nie obniża podłogi — zostaje 5 najnowszych."""
        proj = self._make(8, mtime_start=1700000000.0)
        res = sh.prune_mcp_backups(proj, keep_latest=1)
        self.assertEqual(res["removed"], 3)
        self.assertEqual(res["kept"], 5)
        self.assertEqual(res["freed_mb"], 1.5)   # 3 x 0.5 MB
        left = sorted(p.name for p in (proj / ".jarvis-mcp-backups").iterdir())
        self.assertEqual(left, [f"backup-{i:02d}.bak" for i in range(3, 8)])

    def test_keep_latest_respected_above_floor(self):
        proj = self._make(10, mtime_start=1800000000.0)
        res = sh.prune_mcp_backups(proj, keep_latest=7)
        self.assertEqual(res["kept"], 7)
        self.assertEqual(res["removed"], 3)

    def test_non_bak_and_symlink_untouched(self):
        proj = self._make(6, mtime_start=1900000000.0)
        self._backup_file(proj, "keep.txt", "t" * 4096)
        target = self._backup_file(proj, "orig.bak", "o" * 4096, mtime=1900009999.0)
        link = proj / ".jarvis-mcp-backups" / "link.bak"
        link.symlink_to(target)
        res = sh.prune_mcp_backups(proj, keep_latest=5)
        # 7 realnych .bak (6 z _make + orig.bak): keep 5 (orig.bak najnowszy),
        # removed 2 najstarsze (backup-00, backup-01); symlink pominiety calkowicie
        self.assertEqual(res["removed"], 2)
        self.assertEqual(res["kept"], 5)
        self.assertTrue((proj / ".jarvis-mcp-backups" / "keep.txt").is_file())
        self.assertTrue(link.is_symlink())
        self.assertTrue((proj / ".jarvis-mcp-backups" / "orig.bak").is_file())
        self.assertFalse((proj / ".jarvis-mcp-backups" / "backup-00.bak").exists())
        self.assertFalse((proj / ".jarvis-mcp-backups" / "backup-01.bak").exists())


class InspectStorageTests(StorageBase):
    def test_composite_warnings_and_ro_gate(self):
        self._blk("sda", {"size": 1000, "queue/rotational": 1,
                          "device/hwmon/hwmon0/temp1_input": 60000})   # HDD 60.0 >= 55
        self._blk("sdb", {"size": 1000, "queue/rotational": 0,
                          "device/hwmon/hwmon0/temp1_input": 75000})   # SSD 75.0 >= 72
        self._blk("sdc", {"size": 1000, "queue/rotational": 0,
                          "device/hwmon/hwmon0/temp1_input": 45000})   # 45.0 OK
        mounts = self._mounts(["/dev/sda1 /data ext4 ro 0 0"])
        proj = self.base / "proj"
        for i in range(61):
            self._backup_file(proj, f"{i}.bak", "z" * 4096)

        res = sh.inspect_storage(project_dir=proj,
                                 sys_block=self.base / "sys" / "block",
                                 proc_mounts=mounts)
        self.assertFalse(res["ok"])                       # ro gates ok
        self.assertEqual(len(res["drives"]), 3)
        self.assertEqual(res["mounts"]["readonly_alerts"][0]["mountpoint"], "/data")
        self.assertEqual(res["mcp_backups"]["count"], 61)
        warnings_text = " ".join(res["warnings"])
        self.assertIn("zamontowany w trybie tylko do odczytu", warnings_text)
        self.assertIn("Wysoka temperatura dysku sda (HDD): 60.0°C", warnings_text)
        self.assertIn("Wysoka temperatura dysku sdb (SSD): 75.0°C", warnings_text)
        self.assertFalse(any("sdc" in w for w in res["warnings"]))
        self.assertTrue(any("61 kopii" in w for w in res["warnings"]))
        self.assertAlmostEqual(res["checked_at"], time.time(), delta=10.0)

    def test_clean_world_ok_without_warnings(self):
        res = sh.inspect_storage(project_dir=None,
                                 sys_block=self.base / "sys" / "block",
                                 proc_mounts=self._mounts(["/dev/sda1 /data ext4 rw 0 0"]))
        self.assertTrue(res["ok"])
        self.assertEqual(res["warnings"], [])
        self.assertEqual(res["mcp_backups"], {"count": 0, "total_mb": 0.0})


if __name__ == "__main__":
    unittest.main()
