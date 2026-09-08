import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from media_generator import verify_confidential_gpu

logger = logging.getLogger(__name__)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def calculate_frames_behind(frames_processed, elapsed_seconds, target_fps):
    expected_frames = int(max(0, elapsed_seconds) * target_fps)
    return max(0, expected_frames - frames_processed)


def intersection_over_union(first, second):
    left = max(first[0], second[0])
    top = max(first[1], second[1])
    right = min(first[2], second[2])
    bottom = min(first[3], second[3])
    intersection = max(0, right - left) * max(0, bottom - top)
    first_area = max(0, first[2] - first[0]) * max(0, first[3] - first[1])
    second_area = max(0, second[2] - second[0]) * max(0, second[3] - second[1])
    union = first_area + second_area - intersection
    return intersection / union if union else 0.0


def prepare_face_boxes(boxes, probabilities, width, height, threshold, margin):
    if boxes is None:
        if probabilities is None:
            return []
        try:
            if all(probability is None for probability in probabilities):
                return []
        except TypeError:
            pass
        raise RuntimeError('Face detector returned malformed results')
    if probabilities is None or len(boxes) != len(probabilities):
        raise RuntimeError('Face detector returned malformed results')

    prepared = []
    for box, probability in zip(boxes, probabilities):
        if probability is None or float(probability) < threshold:
            continue
        if box is None or len(box) != 4:
            raise RuntimeError('Face detector returned a malformed bounding box')
        left, top, right, bottom = (float(value) for value in box)
        if right <= left or bottom <= top:
            raise RuntimeError('Face detector returned an invalid bounding box')
        horizontal_margin = (right - left) * margin
        vertical_margin = (bottom - top) * margin
        prepared_box = (
            max(0, int(left - horizontal_margin)),
            max(0, int(top - vertical_margin)),
            min(width, int(right + horizontal_margin + 0.999)),
            min(height, int(bottom + vertical_margin + 0.999)),
        )
        if prepared_box[2] > prepared_box[0] and prepared_box[3] > prepared_box[1]:
            prepared.append(prepared_box)
    return prepared


class FaceBoxTracker:
    def __init__(self, hold_frames=3, match_threshold=0.3):
        self.hold_frames = hold_frames
        self.match_threshold = match_threshold
        self._tracks = []

    def update(self, detections):
        current = [(tuple(box), 0) for box in detections]
        for previous_box, missed_frames in self._tracks:
            matched = any(
                intersection_over_union(previous_box, detected_box) >= self.match_threshold
                for detected_box in detections
            )
            if not matched and missed_frames < self.hold_frames:
                current.append((previous_box, missed_frames + 1))
        self._tracks = current
        return [box for box, _ in current]


def blur_face_regions(image, boxes):
    from PIL import ImageFilter

    output = image.copy()
    for box in boxes:
        crop = output.crop(box)
        radius = max(12, int(min(crop.size) * 0.25))
        output.paste(crop.filter(ImageFilter.GaussianBlur(radius=radius)), box)
    return output


class StatusWriter:
    def __init__(self, path):
        self.path = Path(path)

    def write(self, state, **fields):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {'state': state, 'updated_at': _utc_now(), **fields}
        temporary_path = self.path.with_suffix('.tmp')
        temporary_path.write_text(json.dumps(document), encoding='utf-8')
        temporary_path.replace(self.path)


@dataclass(frozen=True)
class AnonymizerConfig:
    source_path: Path
    output_dir: Path
    status_path: Path
    width: int = 1280
    height: int = 720
    fps: int = 12
    confidence_threshold: float = 0.90
    box_margin: float = 0.20
    hold_frames: int = 3
    playlist_size: int = 6

    @classmethod
    def from_environment(cls):
        root = Path(os.environ.get(
            'CCTV_PROCESSING_ROOT', '/var/lib/citizen-registry/cctv'))
        return cls(
            source_path=Path(os.environ.get(
                'CCTV_VIDEO_PATH',
                '/opt/citizen-registry/source-media/'
                'london-marathon-2026-close-faces.mp4')),
            output_dir=root / 'hls',
            status_path=root / 'status.json',
            width=int(os.environ.get('CCTV_OUTPUT_WIDTH', '1280')),
            height=int(os.environ.get('CCTV_OUTPUT_HEIGHT', '720')),
            fps=int(os.environ.get('CCTV_OUTPUT_FPS', '12')),
            confidence_threshold=float(os.environ.get(
                'CCTV_FACE_CONFIDENCE', '0.90')),
            box_margin=float(os.environ.get('CCTV_FACE_MARGIN', '0.20')),
            hold_frames=int(os.environ.get('CCTV_FACE_HOLD_FRAMES', '3')),
            playlist_size=int(os.environ.get('CCTV_HLS_PLAYLIST_SIZE', '6')),
        )


class VideoAnonymizer:
    def __init__(self, config, process_factory=subprocess.Popen):
        self.config = config
        self.process_factory = process_factory
        self.status = StatusWriter(config.status_path)
        self.playlist_path = config.output_dir / 'index.m3u8'

    def decoder_command(self):
        video_filter = (
            f'fps={self.config.fps},scale={self.config.width}:{self.config.height}:'
            'force_original_aspect_ratio=decrease,'
            f'pad={self.config.width}:{self.config.height}:(ow-iw)/2:(oh-ih)/2:black'
        )
        return [
            'ffmpeg', '-hide_banner', '-loglevel', 'error', '-re',
            '-i', str(self.config.source_path), '-an',
            '-vf', video_filter, '-pix_fmt', 'rgb24', '-f', 'rawvideo', 'pipe:1',
        ]

    def encoder_command(self):
        segment_pattern = self.config.output_dir / 'segment-%08d.ts'
        return [
            'ffmpeg', '-hide_banner', '-loglevel', 'error',
            '-f', 'rawvideo', '-pixel_format', 'rgb24',
            '-video_size', f'{self.config.width}x{self.config.height}',
            '-framerate', str(self.config.fps), '-i', 'pipe:0', '-an',
            '-c:v', 'libx264', '-preset', 'veryfast', '-tune', 'zerolatency',
            '-pix_fmt', 'yuv420p', '-flags', '+cgop',
            '-g', str(self.config.fps), '-keyint_min', str(self.config.fps),
            '-sc_threshold', '0', '-f', 'hls', '-hls_time', '1',
            '-hls_list_size', '0', '-hls_playlist_type', 'event',
            '-hls_flags', 'independent_segments+temp_file',
            '-hls_segment_filename', str(segment_pattern), str(self.playlist_path),
        ]

    @staticmethod
    def _read_frame(stream, frame_size):
        frame = bytearray()
        while len(frame) < frame_size:
            chunk = stream.read(frame_size - len(frame))
            if not chunk:
                if frame:
                    raise RuntimeError('Decoder returned a partial video frame')
                return None
            frame.extend(chunk)
        return bytes(frame)

    def _remove_published_output(self):
        self.playlist_path.unlink(missing_ok=True)
        for segment_path in self.config.output_dir.glob('segment-*.ts*'):
            segment_path.unlink(missing_ok=True)

    @staticmethod
    def _stop_process(process):
        if process is None:
            return
        for stream_name in ('stdin', 'stdout'):
            stream = getattr(process, stream_name, None)
            if stream:
                stream.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    @staticmethod
    def _abort_process(process):
        if process is None:
            return
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for stream_name in ('stdin', 'stdout'):
            stream = getattr(process, stream_name, None)
            if stream:
                stream.close()

    def run(self):
        from PIL import Image
        import torch
        from facenet_pytorch import MTCNN

        if not self.config.source_path.is_file():
            raise RuntimeError(f'CCTV source video is unavailable: {self.config.source_path}')

        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self._remove_published_output()
        self.status.write('starting', message='Verifying confidential GPU')
        decoder = None
        encoder = None
        frames_processed = 0
        faces_detected = 0
        started_at = time.monotonic()
        last_status_at = started_at
        try:
            confidential_gpu = verify_confidential_gpu(torch)
            detector = MTCNN(keep_all=True, device='cuda:0', post_process=False)
            tracker = FaceBoxTracker(self.config.hold_frames)
            decoder = self.process_factory(
                self.decoder_command(), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            encoder = self.process_factory(
                self.encoder_command(), stdin=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            frame_size = self.config.width * self.config.height * 3
            started_at = time.monotonic()
            last_status_at = started_at

            while True:
                frame_bytes = self._read_frame(decoder.stdout, frame_size)
                if frame_bytes is None:
                    encoder.stdin.close()
                    return_code = encoder.wait(timeout=30)
                    if return_code != 0:
                        raise RuntimeError(
                            f'Encoder failed while finalizing HLS output: {return_code}')
                    encoder = None
                    elapsed = max(time.monotonic() - started_at, 0.001)
                    self.status.write(
                        'completed',
                        message='Confidential face anonymization is complete',
                        frames_processed=frames_processed,
                        current_faces=0,
                        faces_detected=faces_detected,
                        processing_fps=round(frames_processed / elapsed, 1),
                        frames_behind=0,
                        lag_scale_frames=self.config.fps * self.config.playlist_size,
                        output=f'{self.config.width}x{self.config.height}@{self.config.fps}',
                        detector='facenet-pytorch MTCNN (detection only)',
                        confidence_threshold=self.config.confidence_threshold,
                        confidential_gpu=confidential_gpu,
                    )
                    break
                image = Image.frombytes(
                    'RGB', (self.config.width, self.config.height), frame_bytes)
                with torch.inference_mode():
                    boxes, probabilities = detector.detect(image)
                detected_boxes = prepare_face_boxes(
                    boxes, probabilities, self.config.width, self.config.height,
                    self.config.confidence_threshold, self.config.box_margin)
                tracked_boxes = tracker.update(detected_boxes)
                anonymized = blur_face_regions(image, tracked_boxes)
                encoder.stdin.write(anonymized.tobytes())
                frames_processed += 1
                faces_detected += len(detected_boxes)

                current_time = time.monotonic()
                if current_time - last_status_at >= 1:
                    elapsed = max(current_time - started_at, 0.001)
                    state = 'processing' if self.playlist_path.is_file() else 'starting'
                    self.status.write(
                        state,
                        message='Confidential face anonymization is active',
                        frames_processed=frames_processed,
                        current_faces=len(detected_boxes),
                        faces_detected=faces_detected,
                        processing_fps=round(frames_processed / elapsed, 1),
                        frames_behind=calculate_frames_behind(
                            frames_processed, elapsed, self.config.fps),
                        lag_scale_frames=self.config.fps * self.config.playlist_size,
                        output=f'{self.config.width}x{self.config.height}@{self.config.fps}',
                        detector='facenet-pytorch MTCNN (detection only)',
                        confidence_threshold=self.config.confidence_threshold,
                        confidential_gpu=confidential_gpu,
                    )
                    last_status_at = current_time
        except Exception as error:
            logger.exception('CCTV anonymization failed')
            self._abort_process(encoder)
            encoder = None
            self._remove_published_output()
            self.status.write(
                'failed', message='Confidential face anonymization is unavailable',
                error=f'{type(error).__name__}: {error}',
                frames_processed=frames_processed,
            )
            raise
        finally:
            self._stop_process(encoder)
            self._stop_process(decoder)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    VideoAnonymizer(AnonymizerConfig.from_environment()).run()