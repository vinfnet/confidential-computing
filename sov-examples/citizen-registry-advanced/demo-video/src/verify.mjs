import { readFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const outputDir = path.join(root, 'output');
const master = path.join(outputDir, 'citizen-registry-sovereignty-demo-master.mp4');
const captionsPath = path.join(outputDir, 'captions.vtt');
const manifestPath = path.join(outputDir, 'run-manifest.json');
const timeline = JSON.parse(await readFile(path.join(root, 'src', 'timeline.json'), 'utf8'));
const failures = [];

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`${command} failed (${code}): ${stderr.trim()}`)));
  });
}

await stat(master);
const probe = JSON.parse((await run('ffprobe', ['-v', 'error', '-show_entries', 'format=duration:stream=index,codec_type,codec_name,width,height,r_frame_rate,sample_rate', '-of', 'json', master])).stdout);
const duration = Number(probe.format.duration);
const video = probe.streams.find(stream => stream.codec_type === 'video');
const audio = probe.streams.find(stream => stream.codec_type === 'audio');
const subtitles = probe.streams.find(stream => stream.codec_type === 'subtitle');
if (Math.abs(duration - timeline.durationSeconds) > 0.05) failures.push(`Duration is ${duration}, expected ${timeline.durationSeconds} seconds.`);
if (video?.codec_name !== 'h264' || video.width !== 1920 || video.height !== 1080 || video.r_frame_rate !== '30/1') failures.push('Video must be H.264, 1920x1080, 30 fps.');
if (audio?.codec_name !== 'aac' || audio.sample_rate !== '48000') failures.push('Audio must be AAC at 48 kHz.');
if (subtitles?.codec_name !== 'mov_text') failures.push('English soft captions are missing.');

const volumeOutput = (await run('ffmpeg', ['-v', 'info', '-i', master, '-map', '0:a:0', '-af', 'volumedetect', '-f', 'null', '-'])).stderr;
const meanVolume = Number(volumeOutput.match(/mean_volume:\s*(-?[\d.]+) dB/)?.[1]);
if (!Number.isFinite(meanVolume) || meanVolume < -40) failures.push('Narration audio is silent or too quiet.');

const blackOutput = (await run('ffmpeg', ['-v', 'info', '-i', master, '-t', '3', '-vf', 'blackdetect=d=1:pix_th=0.10', '-an', '-f', 'null', '-'])).stderr;
const openingBlack = [...blackOutput.matchAll(/black_start:([\d.]+) black_end:([\d.]+) black_duration:([\d.]+)/g)]
  .some(match => Number(match[1]) < 0.1 && Number(match[3]) >= 1);
if (openingBlack) failures.push('Opening contains a blank or black interval of at least one second.');

const captions = await readFile(captionsPath, 'utf8');
if (!captions.startsWith('WEBVTT') || (captions.match(/-->/g)?.length || 0) < 6) failures.push('Caption sidecar is invalid or incomplete.');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
if (!manifest.passed || manifest.mode !== 'record') failures.push('A successful recorded-take manifest is required.');
if (manifest.durationSeconds !== timeline.durationSeconds) failures.push('Recorded-take duration does not match the current timeline.');
for (const required of ['openingArchitecture', 'openPassport', 'closePassport', 'openHistory', 'askAverageAge', 'askSalaryBands', 'showBoundary']) {
  if (!manifest.actions.some(action => action.handler === required && action.ok)) failures.push(`Required checkpoint failed or is missing: ${required}.`);
}

if (failures.length) throw new Error(`Media verification failed:\n- ${failures.join('\n- ')}`);
console.log(`Media verification passed: ${duration.toFixed(3)}s, H.264 1920x1080@30, AAC 48kHz, captions, audible narration, nonblank opening.`);