import hashlib
import json
import logging
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def get_gpu_attestation_evidence():
    attestation_path = Path(os.environ.get(
        'GPU_ATTESTATION_PATH',
        '/var/lib/citizen-registry/gpu-attestation.json'))
    try:
        attestation = json.loads(attestation_path.read_text(encoding='utf-8'))
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(
            encoding='utf-8').strip()
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'verified': False,
            'current_boot': False,
            'status': 'evidence unavailable',
        }

    current_boot = attestation.get('boot_id') == boot_id
    verified = bool(attestation.get('verified')) and current_boot
    return {
        'verified': verified,
        'current_boot': current_boot,
        'cc_status': attestation.get('cc_status', 'not reported'),
        'environment': attestation.get('environment', 'not reported'),
        'gpu': attestation.get('gpu', 'NVIDIA H100'),
        'verifier': attestation.get('verifier', 'NVIDIA nvtrust'),
        'result': attestation.get('result', 'not reported'),
        'report_sha256': attestation.get('report_sha256', 'not reported'),
        'onboarding_release': attestation.get('onboarding_release', 'not reported'),
        'attested_at': attestation.get('attested_at', 'not reported'),
        'boot_id': attestation.get('boot_id', 'not reported'),
        'status': 'verified for current boot' if verified else 'stale or unverified',
    }


def verify_confidential_gpu(torch_module):
    if not torch_module.cuda.is_available():
        raise RuntimeError('CUDA is required; CPU image generation is disabled')

    device_name = torch_module.cuda.get_device_name(0)
    if 'H100' not in device_name.upper():
        raise RuntimeError(f'An NVIDIA H100 is required, found: {device_name}')

    result = subprocess.run(
        ['nvidia-smi', 'conf-compute', '-f'],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    confidential_compute_output = result.stdout + result.stderr
    if confidential_compute_output.strip() != 'CC status: ON':
        raise RuntimeError('NVIDIA H100 confidential-compute mode is not active')

    environment_result = subprocess.run(
        ['nvidia-smi', 'conf-compute', '-e'],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if (environment_result.stdout + environment_result.stderr).strip() != \
            'CC Environment: PRODUCTION':
        raise RuntimeError('NVIDIA H100 is not in the production CC environment')

    attestation = get_gpu_attestation_evidence()
    if not attestation['verified']:
        raise RuntimeError('Confidential GPU was not attested during the current VM boot')

    properties = torch_module.cuda.get_device_properties(0)
    return {
        'verified': True,
        'mode': 'on',
        'environment': 'production',
        'attested': True,
        'device': device_name,
        'memory_gib': round(properties.total_memory / (1024 ** 3), 1),
        'compute_capability': f'{properties.major}.{properties.minor}',
        'inference_device': 'cuda:0',
        'cpu_tee': 'AMD SEV-SNP',
    }


class MediaGenerator:
    def __init__(self, root=None, model_id=None):
        self.root = Path(root or os.environ.get(
            'CITIZEN_MEDIA_ROOT', '/var/lib/citizen-registry/media'))
        self.model_id = model_id or os.environ.get(
            'PORTRAIT_MODEL_ID', 'stabilityai/sdxl-turbo')
        self.status_path = self.root / 'status.json'
        self.lock_path = self.root / 'generation.lock'
        self._start_lock = threading.Lock()
        self._started_fingerprint = None

    def status(self):
        try:
            return json.loads(self.status_path.read_text(encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'state': 'pending',
                'completed': 0,
                'total': 0,
                'percent': 0,
                'message': 'Waiting for citizen records',
            }

    def portrait_path(self, citizen_id):
        return self.root / f'{int(citizen_id)}-portrait.jpg'

    def credential_path(self, citizen_id):
        return self.root / f'{int(citizen_id)}-credential.jpg'

    def ensure_started(self, citizens):
        snapshot = [dict(citizen) for citizen in citizens]
        fingerprint = self._fingerprint(snapshot)
        with self._start_lock:
            if self._started_fingerprint == fingerprint:
                return
            self._started_fingerprint = fingerprint
            threading.Thread(
                target=self._generate_all,
                args=(snapshot, fingerprint),
                daemon=True,
                name='citizen-media-generator',
            ).start()

    @staticmethod
    def _fingerprint(citizens):
        identity_fields = [
            (citizen['id'], citizen['national_id'], citizen['first_name'],
             citizen['last_name'], citizen['date_of_birth'],
             citizen.get('region'), citizen.get('municipality'))
            for citizen in citizens
        ]
        payload = json.dumps(identity_fields, separators=(',', ':'), sort_keys=False)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _write_status(
            self, state, completed, total, message, fingerprint, error=None,
            confidential_gpu=None):
        self.root.mkdir(parents=True, exist_ok=True)
        document = {
            'state': state,
            'completed': completed,
            'total': total,
            'percent': round((completed / total) * 100) if total else 0,
            'message': message,
            'fingerprint': fingerprint,
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'backend': 'CUDA',
            'model': self.model_id,
        }
        if confidential_gpu:
            document['confidential_gpu'] = confidential_gpu
        if error:
            document['error'] = error
        temporary_path = self.status_path.with_suffix('.tmp')
        temporary_path.write_text(json.dumps(document), encoding='utf-8')
        temporary_path.replace(self.status_path)

    def _generate_all(self, citizens, fingerprint):
        import fcntl

        self.root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open('w', encoding='utf-8') as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return

            total = len(citizens)
            try:
                import torch
                from diffusers import AutoPipelineForText2Image

                confidential_gpu = verify_confidential_gpu(torch)

                previous_fingerprint = self.status().get('fingerprint')
                if previous_fingerprint and previous_fingerprint != fingerprint:
                    for asset_path in self.root.glob('*-portrait.jpg'):
                        asset_path.unlink()
                    for asset_path in self.root.glob('*-credential.jpg'):
                        asset_path.unlink()

                self._write_status(
                    'loading', 0, total, 'Loading portrait model into confidential GPU memory',
                    fingerprint, confidential_gpu=confidential_gpu,
                )
                pipeline = AutoPipelineForText2Image.from_pretrained(
                    self.model_id,
                    torch_dtype=torch.float16,
                    variant='fp16',
                    use_safetensors=True,
                ).to('cuda')
                pipeline.set_progress_bar_config(disable=True)

                completed = 0
                for citizen in citizens:
                    portrait_path = self.portrait_path(citizen['id'])
                    credential_path = self.credential_path(citizen['id'])
                    if not portrait_path.exists() or not credential_path.exists():
                        self._write_status(
                            'generating', completed, total,
                            f"Generating fictional credential {completed + 1} of {total}",
                            fingerprint, confidential_gpu=confidential_gpu,
                        )
                        portrait = self._generate_portrait(pipeline, torch, citizen)
                        self._save_assets(portrait, citizen, portrait_path, credential_path)
                    completed += 1
                    self._write_status(
                        'generating', completed, total,
                        f'Generated {completed} of {total} fictional credentials',
                        fingerprint, confidential_gpu=confidential_gpu,
                    )

                del pipeline
                torch.cuda.empty_cache()
                self._write_status(
                    'complete', total, total,
                    'All fictional citizen credentials are ready', fingerprint,
                    confidential_gpu=confidential_gpu,
                )
            except Exception as error:
                logger.exception('GPU media generation failed')
                self._write_status(
                    'failed', 0, total, 'GPU media generation failed', fingerprint,
                    error=f'{type(error).__name__}: {error}',
                )

    @staticmethod
    def _generate_portrait(pipeline, torch, citizen):
        seed_bytes = hashlib.sha256(citizen['national_id'].encode('utf-8')).digest()[:8]
        seed = int.from_bytes(seed_bytes, 'big') & 0x7FFFFFFFFFFFFFFF
        prompt = (
            'photorealistic head and shoulders studio portrait of a fictional adult, '
            'neutral expression, looking directly at camera, plain light gray background, '
            'even passport-photo lighting, natural skin detail, conservative everyday clothing, '
            'no text, no logos, no uniform, no document'
        )
        generator = torch.Generator(device='cuda').manual_seed(seed)
        with torch.inference_mode():
            return pipeline(
                prompt=prompt,
                negative_prompt='child, celebrity, text, watermark, logo, uniform, document, blurry',
                num_inference_steps=4,
                guidance_scale=0.0,
                height=512,
                width=512,
                generator=generator,
            ).images[0]

    @staticmethod
    def _save_assets(portrait, citizen, portrait_path, credential_path):
        from PIL import Image, ImageDraw, ImageFont

        portrait = portrait.convert('RGB')
        portrait.thumbnail((420, 520), Image.Resampling.LANCZOS)
        portrait.save(portrait_path, format='JPEG', quality=88, optimize=True)

        credential = Image.new('RGB', (1400, 900), '#d9eef2')
        draw = ImageDraw.Draw(credential)
        title_font = ImageFont.load_default(size=42)
        heading_font = ImageFont.load_default(size=28)
        body_font = ImageFont.load_default(size=24)
        watermark_font = ImageFont.load_default(size=56)

        draw.rectangle((0, 0, 1400, 125), fill='#153f52')
        draw.text((55, 32), 'REPUBLIC OF NORLAND', fill='white', font=title_font)
        draw.text((55, 82), 'FICTIONAL CITIZEN CREDENTIAL', fill='#bce2ea', font=heading_font)
        credential.paste(portrait.resize((390, 490)), (60, 180))

        fields = [
            ('NAME', f"{citizen['first_name']} {citizen['last_name']}"),
            ('CITIZEN NUMBER', citizen['national_id']),
            ('DATE OF BIRTH', citizen['date_of_birth']),
            ('REGION', citizen.get('region') or 'Not recorded'),
            ('MUNICIPALITY', citizen.get('municipality') or 'Not recorded'),
            ('VALID FOR', 'DEMONSTRATION ONLY'),
        ]
        field_y = 190
        for label, value in fields:
            draw.text((510, field_y), label, fill='#42606b', font=heading_font)
            draw.text((510, field_y + 38), str(value), fill='#102f3d', font=body_font)
            field_y += 105

        draw.rectangle((45, 720, 1355, 850), outline='#b42318', width=8)
        draw.text((215, 755), 'NOT A REAL PASSPORT', fill='#b42318', font=watermark_font)
        draw.text(
            (370, 825), 'Fictional demonstration credential - no legal validity',
            fill='#6b1d17', font=body_font,
        )
        credential.save(credential_path, format='JPEG', quality=90, optimize=True)
