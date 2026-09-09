import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from video_anonymizer import (
    AnonymizerConfig,
    FaceBoxTracker,
    StatusWriter,
    VideoAnonymizer,
    blur_face_regions,
    calculate_frames_behind,
    intersection_over_union,
    prepare_face_boxes,
)


class FaceBoxTests(unittest.TestCase):
    def test_accepts_facenet_no_face_result(self):
        boxes = prepare_face_boxes(
            None, [None], width=100, height=80, threshold=0.90, margin=0.20)

        self.assertEqual(boxes, [])

    def test_filters_expands_and_clamps_boxes(self):
        boxes = prepare_face_boxes(
            [[-5, 5, 25, 35], [40, 40, 60, 60]],
            [0.95, 0.50],
            width=100,
            height=80,
            threshold=0.90,
            margin=0.20,
        )

        self.assertEqual(boxes, [(0, 0, 31, 41)])

    def test_rejects_malformed_detector_results(self):
        with self.assertRaisesRegex(RuntimeError, 'malformed results'):
            prepare_face_boxes([[1, 2, 3, 4]], [], 10, 10, 0.9, 0.2)

        with self.assertRaisesRegex(RuntimeError, 'invalid bounding box'):
            prepare_face_boxes([[4, 2, 1, 8]], [0.99], 10, 10, 0.9, 0.2)

    def test_intersection_over_union(self):
        self.assertEqual(intersection_over_union((0, 0, 10, 10), (20, 20, 30, 30)), 0)
        self.assertAlmostEqual(
            intersection_over_union((0, 0, 10, 10), (5, 5, 15, 15)),
            25 / 175,
        )

    def test_tracker_holds_short_detector_misses_then_expires(self):
        tracker = FaceBoxTracker(hold_frames=2)
        face = (10, 10, 30, 30)

        self.assertEqual(tracker.update([face]), [face])
        self.assertEqual(tracker.update([]), [face])
        self.assertEqual(tracker.update([]), [face])
        self.assertEqual(tracker.update([]), [])

    def test_tracker_reuses_current_boxes_without_aging(self):
        tracker = FaceBoxTracker(hold_frames=2)
        face = (10, 10, 30, 30)

        tracker.update([face])

        self.assertEqual(tracker.current(), [face])
        self.assertEqual(tracker.current(), [face])


class FrameProcessingTests(unittest.TestCase):
    def test_frame_lag_compares_completed_frames_with_source_clock(self):
        self.assertEqual(calculate_frames_behind(120, 10, 12), 0)
        self.assertEqual(calculate_frames_behind(80, 10, 12), 40)
        self.assertEqual(calculate_frames_behind(130, 10, 12), 0)

    def test_blur_changes_only_selected_region(self):
        image = Image.new('RGB', (40, 20), 'white')
        for horizontal in range(10, 30):
            for vertical in range(5, 15):
                color = (0, 0, 0) if (horizontal + vertical) % 2 else (255, 255, 255)
                image.putpixel((horizontal, vertical), color)

        blurred = blur_face_regions(image, [(10, 5, 30, 15)])

        self.assertEqual(blurred.getpixel((2, 2)), image.getpixel((2, 2)))
        self.assertNotEqual(blurred.getpixel((15, 10)), image.getpixel((15, 10)))

    def test_partial_frame_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'partial video frame'):
            VideoAnonymizer._read_frame(io.BytesIO(b'123'), 10)

    def test_clean_end_of_stream_returns_none(self):
        self.assertIsNone(VideoAnonymizer._read_frame(io.BytesIO(), 10))


class WorkerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.config = AnonymizerConfig(
            source_path=root / 'source.webm',
            output_dir=root / 'hls',
            status_path=root / 'status.json',
            width=320,
            height=180,
            fps=10,
            detection_fps=5,
        )
        self.worker = VideoAnonymizer(self.config)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_commands_publish_finite_atomic_hls(self):
        decoder = self.worker.decoder_command()
        encoder = self.worker.encoder_command()

        self.assertNotIn('-stream_loop', decoder)
        self.assertNotIn('-re', decoder)
        self.assertIn('rgb24', decoder)
        self.assertIn('libx264', encoder)
        self.assertEqual(encoder[encoder.index('-framerate') + 1], '10')
        self.assertEqual(encoder[encoder.index('-crf') + 1], '20')
        self.assertEqual(encoder[encoder.index('-preset') + 1], 'fast')
        self.assertIn('event', encoder)
        self.assertIn('independent_segments+temp_file', encoder)
        self.assertNotIn('omit_endlist', encoder)
        self.assertEqual(encoder[encoder.index('-hls_list_size') + 1], '0')
        self.assertNotIn('-c:a', encoder)

    def test_default_profile_outputs_24_fps_with_12_fps_detection(self):
        config = AnonymizerConfig.from_environment()

        self.assertEqual(config.fps, 24)
        self.assertEqual(config.detection_fps, 12)
        self.assertEqual(config.detection_interval, 2)
        self.assertEqual(config.detection_batch_size, 4)
        self.assertEqual(config.frame_batch_size, 8)

    def test_rejects_detection_rate_above_output_rate(self):
        with self.assertRaisesRegex(ValueError, 'detection FPS'):
            AnonymizerConfig(
                source_path=self.config.source_path,
                output_dir=self.config.output_dir,
                status_path=self.config.status_path,
                fps=12,
                detection_fps=24,
            )

    def test_status_write_replaces_document_atomically(self):
        writer = StatusWriter(self.config.status_path)
        writer.write('starting', frames_processed=0)
        writer.write('running', frames_processed=10)

        document = json.loads(self.config.status_path.read_text(encoding='utf-8'))
        self.assertEqual(document['state'], 'running')
        self.assertEqual(document['frames_processed'], 10)
        self.assertFalse(self.config.status_path.with_suffix('.tmp').exists())

    def test_output_removal_withholds_stale_playlist_and_segments(self):
        self.config.output_dir.mkdir()
        self.worker.playlist_path.write_text('#EXTM3U', encoding='utf-8')
        (self.config.output_dir / 'segment-00000001.ts').write_bytes(b'old')

        self.worker._remove_published_output()

        self.assertFalse(self.worker.playlist_path.exists())
        self.assertEqual(list(self.config.output_dir.glob('segment-*.ts*')), [])

    def test_abort_kills_process_before_closing_encoder_input(self):
        events = []

        class Stream:
            def close(self):
                events.append('close')

        class Process:
            stdin = Stream()
            stdout = None

            @staticmethod
            def poll():
                return None

            @staticmethod
            def kill():
                events.append('kill')

            @staticmethod
            def wait(timeout):
                events.append(f'wait:{timeout}')

        self.worker._abort_process(Process())

        self.assertEqual(events, ['kill', 'wait:5', 'close'])


if __name__ == '__main__':
    unittest.main()