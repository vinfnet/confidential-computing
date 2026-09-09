import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import dvr_storage


class DvrStorageTests(unittest.TestCase):
    def test_upload_records_recipe_and_digest(self):
        client = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'video.mp4'
            source.write_bytes(b'camera footage')

            with patch.object(dvr_storage, '_blob_client', return_value=client):
                metadata = dvr_storage.upload_dvr_video(
                    'https://private/blob', 'writer-id', source, 'recipe-v1')

        self.assertEqual(metadata['ingest_recipe'], 'recipe-v1')
        self.assertEqual(metadata['source_system'], 'simulated-cctv-dvr')
        self.assertEqual(metadata['source_sha256'], dvr_storage.hashlib.sha256(
            b'camera footage').hexdigest())
        self.assertTrue(client.upload_blob.call_args.kwargs['overwrite'])

    def test_recipe_match_uses_blob_metadata(self):
        client = MagicMock()
        client.get_blob_properties.return_value.metadata = {
            'ingest_recipe': 'recipe-v1'}

        with patch.object(dvr_storage, '_blob_client', return_value=client):
            self.assertTrue(dvr_storage.blob_matches_recipe(
                'https://private/blob', 'writer-id', 'recipe-v1'))
            self.assertFalse(dvr_storage.blob_matches_recipe(
                'https://private/blob', 'writer-id', 'recipe-v2'))

    def test_download_atomically_replaces_verified_file(self):
        payload = b'encrypted-at-rest video'
        client = MagicMock()
        client.get_blob_properties.return_value.metadata = {
            'source_sha256': dvr_storage.hashlib.sha256(payload).hexdigest()}
        client.download_blob.return_value.readinto.side_effect = (
            lambda destination: destination.write(payload))

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'cache' / 'video.mp4'
            with patch.object(dvr_storage, '_blob_client', return_value=client):
                dvr_storage.download_dvr_video(
                    'https://private/blob', 'reader-id', destination)

            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(destination.with_suffix('.mp4.tmp').exists())

    def test_download_rejects_digest_mismatch(self):
        client = MagicMock()
        client.get_blob_properties.return_value.metadata = {
            'source_sha256': '0' * 64}
        client.download_blob.return_value.readinto.side_effect = (
            lambda destination: destination.write(b'corrupt'))

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'video.mp4'
            destination.write_bytes(b'previous verified video')
            with patch.object(dvr_storage, '_blob_client', return_value=client):
                with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                    dvr_storage.download_dvr_video(
                        'https://private/blob', 'reader-id', destination)

            self.assertEqual(destination.read_bytes(), b'previous verified video')
            self.assertFalse(destination.with_suffix('.mp4.tmp').exists())


if __name__ == '__main__':
    unittest.main()
