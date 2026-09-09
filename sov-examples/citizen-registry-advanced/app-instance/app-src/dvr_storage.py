"""Managed-identity transfer helpers for the private CCTV DVR blob."""

import argparse
import hashlib
import os
from pathlib import Path


def _blob_client(blob_uri, client_id):
    from azure.identity import ManagedIdentityCredential
    from azure.storage.blob import BlobClient

    credential = ManagedIdentityCredential(client_id=client_id)
    return BlobClient.from_blob_url(blob_uri, credential=credential)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def blob_matches_recipe(blob_uri, client_id, recipe):
    try:
        properties = _blob_client(blob_uri, client_id).get_blob_properties()
    except Exception:
        return False
    return properties.metadata.get('ingest_recipe') == recipe


def upload_dvr_video(blob_uri, client_id, source_path, recipe):
    source_path = Path(source_path)
    metadata = {
        'ingest_recipe': recipe,
        'source_sha256': sha256_file(source_path),
        'source_system': 'simulated-cctv-dvr',
    }
    with source_path.open('rb') as source:
        _blob_client(blob_uri, client_id).upload_blob(
            source, overwrite=True, metadata=metadata)
    return metadata


def download_dvr_video(blob_uri, client_id, destination_path):
    destination_path = Path(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = destination_path.with_suffix(destination_path.suffix + '.tmp')
    blob_client = _blob_client(blob_uri, client_id)
    properties = blob_client.get_blob_properties()
    with temporary_path.open('wb') as destination:
        blob_client.download_blob().readinto(destination)
    expected_sha256 = properties.metadata.get('source_sha256')
    if expected_sha256 and sha256_file(temporary_path) != expected_sha256:
        temporary_path.unlink(missing_ok=True)
        raise RuntimeError('Downloaded DVR video failed its SHA-256 integrity check')
    os.replace(temporary_path, destination_path)
    return properties.metadata


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('matches', 'upload', 'download'))
    parser.add_argument('--blob-uri', required=True)
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--recipe')
    parser.add_argument('--path')
    args = parser.parse_args()

    if args.operation == 'matches':
        if not args.recipe:
            parser.error('--recipe is required for matches')
        raise SystemExit(0 if blob_matches_recipe(
            args.blob_uri, args.client_id, args.recipe) else 1)
    if not args.path:
        parser.error('--path is required for upload and download')
    if args.operation == 'upload':
        if not args.recipe:
            parser.error('--recipe is required for upload')
        upload_dvr_video(args.blob_uri, args.client_id, args.path, args.recipe)
    else:
        download_dvr_video(args.blob_uri, args.client_id, args.path)


if __name__ == '__main__':
    main()