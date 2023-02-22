"""
<Program Name>
  test_storage.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  April 17, 2020

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'storage.py'
"""

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import securesystemslib.storage
from securesystemslib.exceptions import StorageError


class TestStorage(unittest.TestCase):  # pylint: disable=missing-class-docstring
    def setUp(self):
        self.storage_backend = securesystemslib.storage.FilesystemBackend()
        self.temp_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.filepath = os.path.join(self.temp_dir, "testfile")
        with open(self.filepath, "wb") as test:
            test.write(b"testing")
        self.fileobj = open(  # pylint: disable=consider-using-with
            self.filepath, "rb"
        )

    def tearDown(self):
        self.fileobj.close()
        shutil.rmtree(self.temp_dir)

    def test_exceptions(self):
        invalid_path = ""
        non_existent_path = Path(self.temp_dir) / "not_existent"
        self.assertFalse(non_existent_path.exists())

        with self.assertRaises(StorageError):
            with self.storage_backend.get(non_existent_path) as _:
                pass

        with self.assertRaises(StorageError):
            self.storage_backend.getsize(non_existent_path)

        with self.assertRaises(StorageError):
            self.storage_backend.list_folder(non_existent_path)

        with self.assertRaises(StorageError):
            self.storage_backend.create_folder(invalid_path)

    @unittest.skipIf(os.name == "nt", "n/a on Windows")
    def test_permission_exceptions(self):
        non_writable_path = Path(self.temp_dir) / "not_writable"
        os.mkdir(non_writable_path, mode=stat.S_IRUSR)

        with self.assertRaises(StorageError):
            self.storage_backend.put(self.fileobj, non_writable_path / "new")

        with self.assertRaises(StorageError):
            self.storage_backend.create_folder(non_writable_path / "new")

    def test_files(self):
        with self.storage_backend.get(self.filepath) as get_fileobj:
            self.assertEqual(get_fileobj.read(), self.fileobj.read())

        self.assertEqual(
            self.storage_backend.getsize(self.filepath),
            os.path.getsize(self.filepath),
        )

        put_path = os.path.join(self.temp_dir, "put")
        with self.storage_backend.get(self.filepath) as get_fileobj:
            self.storage_backend.put(get_fileobj, put_path)
            self.fileobj.seek(0)
            with open(put_path, "rb") as put_file:
                self.assertEqual(put_file.read(), self.fileobj.read())

        self.assertTrue(os.path.exists(put_path))
        self.storage_backend.remove(put_path)
        self.assertFalse(os.path.exists(put_path))

    def test_folders(self):
        leaves = ["test1", "test2", "test3"]
        folder = os.path.join(self.temp_dir, "test_dir")
        self.storage_backend.create_folder(folder)
        for leaf in leaves:
            with open(os.path.join(folder, leaf), "wb") as fi:
                fi.write(leaf.encode("utf-8"))
        found_leaves = self.storage_backend.list_folder(folder)
        self.assertListEqual(leaves, sorted(found_leaves))

    def test_singleton(self):
        # There should only ever be a single instance of FilesystemBackend.
        # An object's id is unique and constant for the object during its
        # lifetime. Therefore create more than one instance of FilesystemBackend
        # and compare their id's
        fb1 = securesystemslib.storage.FilesystemBackend()
        fb2 = securesystemslib.storage.FilesystemBackend()
        self.assertEqual(id(fb1), id(fb2))
        self.assertEqual(id(self.storage_backend), id(fb1))
        self.assertEqual(id(fb2), id(self.storage_backend))


if __name__ == "__main__":
    unittest.main()
