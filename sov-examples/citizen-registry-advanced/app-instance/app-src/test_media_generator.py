import subprocess
import json
import unittest
from unittest.mock import Mock, patch

from media_generator import MediaGenerator, get_gpu_attestation_evidence, verify_confidential_gpu


class ConfidentialGpuVerificationTests(unittest.TestCase):
    def setUp(self):
        self.torch = Mock()
        self.torch.cuda.is_available.return_value = True
        self.torch.cuda.get_device_name.return_value = 'NVIDIA H100 NVL'
        self.torch.cuda.get_device_properties.return_value = Mock(
            total_memory=94 * 1024 ** 3,
            major=9,
            minor=0,
        )

    @patch('media_generator.Path.read_text')
    @patch('media_generator.subprocess.run')
    def test_accepts_attested_h100_in_production_cc_mode(self, run, read_text):
        run.side_effect = [
            Mock(stdout='CC status: ON\n', stderr=''),
            Mock(stdout='CC Environment: PRODUCTION\n', stderr=''),
        ]
        read_text.side_effect = [
            json.dumps({'verified': True, 'boot_id': 'current-boot'}),
            'current-boot\n',
        ]

        evidence = verify_confidential_gpu(self.torch)

        self.assertTrue(evidence['verified'])
        self.assertEqual(evidence['device'], 'NVIDIA H100 NVL')
        self.assertEqual(evidence['inference_device'], 'cuda:0')
        self.assertEqual(evidence['environment'], 'production')
        self.assertEqual(run.call_count, 2)

    def test_rejects_cpu_only_runtime(self):
        self.torch.cuda.is_available.return_value = False

        with self.assertRaisesRegex(RuntimeError, 'CUDA is required'):
            verify_confidential_gpu(self.torch)

    def test_rejects_non_h100_gpu(self):
        self.torch.cuda.get_device_name.return_value = 'NVIDIA A100'

        with self.assertRaisesRegex(RuntimeError, 'H100 is required'):
            verify_confidential_gpu(self.torch)

    @patch('media_generator.subprocess.run')
    def test_rejects_h100_without_confidential_compute_mode(self, run):
        run.return_value = Mock(
            stdout='CC status: OFF\n', stderr='')

        with self.assertRaisesRegex(RuntimeError, 'not active'):
            verify_confidential_gpu(self.torch)

    @patch('media_generator.subprocess.run')
    def test_propagates_nvidia_smi_failure(self, run):
        run.side_effect = subprocess.CalledProcessError(1, 'nvidia-smi')

        with self.assertRaises(subprocess.CalledProcessError):
            verify_confidential_gpu(self.torch)

    @patch('media_generator.Path.read_text')
    @patch('media_generator.subprocess.run')
    def test_rejects_attestation_from_previous_boot(self, run, read_text):
        run.side_effect = [
            Mock(stdout='CC status: ON\n', stderr=''),
            Mock(stdout='CC Environment: PRODUCTION\n', stderr=''),
        ]
        read_text.side_effect = [
            json.dumps({'verified': True, 'boot_id': 'old-boot'}),
            'current-boot\n',
        ]

        with self.assertRaisesRegex(RuntimeError, 'current VM boot'):
            verify_confidential_gpu(self.torch)

    @patch('media_generator.Path.read_text')
    def test_surfaces_current_boot_attestation_evidence(self, read_text):
        read_text.side_effect = [
            json.dumps({
                'verified': True,
                'boot_id': 'current-boot',
                'cc_status': 'ON',
                'environment': 'PRODUCTION',
                'result': 'GPU Attestation is Successful.',
                'report_sha256': 'abc123',
            }),
            'current-boot\n',
        ]

        evidence = get_gpu_attestation_evidence()

        self.assertTrue(evidence['verified'])
        self.assertEqual(evidence['result'], 'GPU Attestation is Successful.')
        self.assertEqual(evidence['report_sha256'], 'abc123')


class PortraitPromptTests(unittest.TestCase):
    def test_prompt_uses_explicit_synthetic_identity_profile(self):
        pipeline = Mock()
        pipeline.return_value.images = ['portrait']
        torch = Mock()
        torch.Generator.return_value.manual_seed.return_value = Mock()
        torch.inference_mode.return_value.__enter__ = Mock()
        torch.inference_mode.return_value.__exit__ = Mock(return_value=False)
        citizen = {
            'national_id': 'NLD-00A-0001X',
            'date_of_birth': '1990-01-01',
            'sex': 'X',
            'portrait_profile': 'East African',
        }

        result = MediaGenerator._generate_portrait(pipeline, torch, citizen)

        prompt = pipeline.call_args.kwargs['prompt']
        self.assertIn('non-binary adult with an androgynous presentation', prompt)
        self.assertIn('East African heritage', prompt)
        self.assertIn('exactly one person and one face', prompt)
        self.assertIn('multiple people', pipeline.call_args.kwargs['negative_prompt'])
        self.assertEqual(result, 'portrait')

    def test_fingerprint_changes_with_gender_or_portrait_profile(self):
        citizen = {
            'id': 1,
            'national_id': 'NLD-00A-0001X',
            'first_name': 'Amani',
            'last_name': 'Njoroge',
            'date_of_birth': '1990-01-01',
            'sex': 'X',
            'portrait_profile': 'East African',
            'region': 'Central',
            'municipality': 'Alderwick',
        }
        original = MediaGenerator._fingerprint([citizen])

        changed = dict(citizen, portrait_profile='West African')
        self.assertNotEqual(original, MediaGenerator._fingerprint([changed]))


if __name__ == '__main__':
    unittest.main()