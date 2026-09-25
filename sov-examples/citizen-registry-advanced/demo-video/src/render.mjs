import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const outputDir = path.join(root, 'output');
const browserVideo = path.join(outputDir, 'browser.webm');
const narration = path.join(outputDir, 'narration.wav');
const captions = path.join(outputDir, 'captions.vtt');
const architectureFrame = path.join(outputDir, 'screenshots', '00-architecture.png');
const master = path.join(outputDir, 'citizen-registry-sovereignty-demo-master.mp4');
const presentation = path.join(outputDir, 'citizen-registry-sovereignty-demo.mp4');
const timeline = JSON.parse(await readFile(path.join(root, 'src', 'timeline.json'), 'utf8'));
const runManifest = JSON.parse(await readFile(path.join(outputDir, 'run-manifest.json'), 'utf8'));
const architectureReadyAt = runManifest.actions.find(action => action.handler === 'openingArchitecture')?.elapsedSeconds;
if (!Number.isFinite(architectureReadyAt) || architectureReadyAt <= 0) throw new Error('Recorded architecture-ready offset is missing from the run manifest.');
if (runManifest.durationSeconds !== timeline.durationSeconds) throw new Error('Recorded take duration does not match the current timeline.');

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve() : reject(new Error(`${command} failed (${code}): ${stderr.trim()}`)));
  });
}

await mkdir(outputDir, { recursive: true });
const videoFilter = `scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black,fps=30,trim=duration=${timeline.durationSeconds},setpts=PTS-STARTPTS`;
const openingFilter = `scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black,fps=30,trim=duration=${architectureReadyAt},setpts=PTS-STARTPTS`;
const audioFilter = `loudnorm=I=-16:TP=-1.5:LRA=7,apad,atrim=duration=${timeline.durationSeconds},asetpts=PTS-STARTPTS`;
await run('ffmpeg', [
  '-y',
  '-i', browserVideo,
  '-loop', '1', '-i', architectureFrame,
  '-i', narration,
  '-i', captions,
  '-filter_complex', `[0:v]${videoFilter}[browser];[1:v]${openingFilter}[opening];[browser][opening]overlay=eof_action=pass[video];[2:a]${audioFilter}[audio]`,
  '-map', '[video]',
  '-map', '[audio]',
  '-map', '3:0',
  '-c:v', 'libx264',
  '-profile:v', 'high',
  '-preset', 'slow',
  '-crf', '18',
  '-pix_fmt', 'yuv420p',
  '-r', '30',
  '-c:a', 'aac',
  '-b:a', '192k',
  '-ar', '48000',
  '-c:s', 'mov_text',
  '-metadata:s:s:0', 'language=eng',
  '-metadata:s:s:0', 'title=English',
  '-movflags', '+faststart',
  '-t', String(timeline.durationSeconds),
  master,
]);
await copyFile(master, presentation);
console.log(`Rendered ${path.relative(root, master)} and ${path.relative(root, presentation)}.`);