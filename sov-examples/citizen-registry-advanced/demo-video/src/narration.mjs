import { AzureCliCredential } from '@azure/identity';
import sdk from 'microsoft-cognitiveservices-speech-sdk';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const scriptPath = path.join(root, '..', 'citizen-registry-sovereignty-demo-script.md');
const timeline = JSON.parse(await readFile(path.join(root, 'src', 'timeline.json'), 'utf8'));
const outputDir = path.join(root, 'output');
const clipsDir = path.join(outputDir, 'narration-clips');
const voice = 'en-GB-RyanNeural';

function timestampSeconds(value) {
  const [minutes, seconds] = value.split(':').map(Number);
  return minutes * 60 + seconds;
}

function parseSections(markdown) {
  const headingPattern = /^## (\d+:\d+)-(\d+:\d+) \| (.+)$/gm;
  const headings = [...markdown.matchAll(headingPattern)];
  return headings.map((heading, index) => {
    const blockStart = heading.index + heading[0].length;
    const blockEnd = headings[index + 1]?.index ?? markdown.length;
    const block = markdown.slice(blockStart, blockEnd);
    const say = block.match(/\*\*Say:\*\*\s*\r?\n([\s\S]*?)(?=\r?\n\*\*|$)/)?.[1] || '';
    const text = say.split(/\r?\n/)
      .filter(line => line.startsWith('>'))
      .map(line => line.replace(/^>\s?/, '').trim())
      .filter(Boolean)
      .join(' ');
    const start = timestampSeconds(heading[1]);
    const end = timestampSeconds(heading[2]);
    return { id: timeline.sections[index]?.id, title: heading[3], start, end, duration: end - start, text };
  }).filter(section => section.text);
}

function countWords(text) {
  return text.match(/[\p{L}\p{N}]+(?:['’-][\p{L}\p{N}]+)*/gu)?.length || 0;
}

function escapeXml(text) {
  return text.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`${command} failed (${code}): ${stderr.trim()}`)));
  });
}

async function durationSeconds(filePath) {
  const { stdout } = await run('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', filePath]);
  return Number(stdout.trim());
}

async function synthesizeClip(speechConfig, section, rate, outputPath) {
  const audioConfig = sdk.AudioConfig.fromAudioFileOutput(outputPath);
  const synthesizer = new sdk.SpeechSynthesizer(speechConfig, audioConfig);
  const boundaries = [];
  synthesizer.wordBoundary = (_, event) => boundaries.push({
    offsetSeconds: event.audioOffset / 10_000_000,
    durationSeconds: event.duration / 10_000,
    text: event.text,
  });
  const ssml = `<speak version="1.0" xml:lang="en-GB"><voice name="${voice}"><prosody rate="${rate >= 0 ? '+' : ''}${rate}%">${escapeXml(section.text)}</prosody></voice></speak>`;
  await new Promise((resolve, reject) => synthesizer.speakSsmlAsync(ssml, result => {
    synthesizer.close();
    if (result.reason === sdk.ResultReason.SynthesizingAudioCompleted) resolve();
    else reject(new Error(result.errorDetails || `Speech synthesis failed: ${result.reason}`));
  }, error => {
    synthesizer.close();
    reject(new Error(String(error)));
  }));
  return boundaries;
}

function vttTimestamp(seconds) {
  const milliseconds = Math.max(0, Math.round(seconds * 1000));
  const hours = Math.floor(milliseconds / 3_600_000);
  const minutes = Math.floor((milliseconds % 3_600_000) / 60_000);
  const remainder = (milliseconds % 60_000) / 1000;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${remainder.toFixed(3).padStart(6, '0')}`;
}

function makeCues(section, boundaries, clipDuration) {
  if (!boundaries.length) {
    const words = section.text.match(/[^\s]+/g) || [];
    boundaries = words.map((text, index) => ({ text, offsetSeconds: clipDuration * index / words.length }));
  }
  const cues = [];
  for (let index = 0; index < boundaries.length; index += 8) {
    const group = boundaries.slice(index, index + 8);
    const next = boundaries[index + 8];
    cues.push({
      start: section.start + group[0].offsetSeconds,
      end: Math.min(section.end, section.start + (next?.offsetSeconds ?? clipDuration)),
      text: group.map(word => word.text).join(' '),
    });
  }
  return cues;
}

const markdown = await readFile(scriptPath, 'utf8');
const sections = parseSections(markdown);
if (sections.length !== timeline.sections.length) throw new Error(`Expected ${timeline.sections.length} narrated sections, found ${sections.length}.`);
const analysis = sections.map(section => {
  const words = countWords(section.text);
  return { ...section, words, impliedWordsPerMinute: Number((words * 60 / section.duration).toFixed(1)) };
});

if (process.argv.includes('--analyze')) {
  console.table(analysis.map(({ title, duration, words, impliedWordsPerMinute }) => ({ title, duration, words, impliedWordsPerMinute })));
  const rushed = analysis.filter(section => section.impliedWordsPerMinute > 200);
  if (rushed.length) throw new Error(`Narration exceeds 200 WPM in: ${rushed.map(section => section.title).join(', ')}`);
  process.exit(0);
}

if (!process.argv.includes('--synthesize')) throw new Error('Specify --analyze or --synthesize.');
const resourceId = process.env.AZURE_SPEECH_RESOURCE_ID;
const endpoint = process.env.AZURE_SPEECH_ENDPOINT;
const tenantId = process.env.AZURE_TENANT_ID;
const region = process.env.AZURE_SPEECH_REGION || 'westeurope';
if (!resourceId || !endpoint || !tenantId) throw new Error('AZURE_SPEECH_RESOURCE_ID, AZURE_SPEECH_ENDPOINT, and AZURE_TENANT_ID are required for Entra-authenticated narration synthesis.');
await mkdir(clipsDir, { recursive: true });

const credential = new AzureCliCredential({ tenantId });
const accessToken = await credential.getToken('https://cognitiveservices.azure.com/.default');
if (!accessToken?.token) throw new Error('Azure CLI did not return a Cognitive Services access token.');
const synthesisEndpoint = new URL('/tts/cognitiveservices/websocket/v1', endpoint);
synthesisEndpoint.protocol = 'wss:';
const speechConfig = sdk.SpeechConfig.fromEndpoint(synthesisEndpoint);
speechConfig.authorizationToken = `aad#${resourceId}#${accessToken.token}`;
speechConfig.speechSynthesisVoiceName = voice;
speechConfig.speechSynthesisOutputFormat = sdk.SpeechSynthesisOutputFormat.Riff48Khz16BitMonoPcm;
const rates = [0, 4, 8, 12, 16, 20];
const clipResults = [];
const cues = [];

for (const section of analysis) {
  let selected = null;
  for (const rate of rates) {
    const clipPath = path.join(clipsDir, `${String(section.start).padStart(3, '0')}-${section.id}.wav`);
    const boundaries = await synthesizeClip(speechConfig, section, rate, clipPath);
    const clipDuration = await durationSeconds(clipPath);
    console.log(`${section.id}: rate ${rate >= 0 ? '+' : ''}${rate}% produced ${clipDuration.toFixed(3)}s for a ${section.duration}s window.`);
    const maximumDuration = section.id === 'close' ? section.duration + 0.1 : section.duration - 0.1;
    if (clipDuration <= maximumDuration) {
      selected = { ...section, rate, clipPath, clipDuration, boundaries };
      break;
    }
  }
  if (!selected) throw new Error(`${section.title} narration does not fit its ${section.duration}-second window at a natural rate.`);
  clipResults.push(selected);
  cues.push(...makeCues(selected, selected.boundaries, selected.clipDuration));
}

const filterInputs = [];
const filterParts = [];
clipResults.forEach((clip, index) => {
  filterInputs.push('-i', clip.clipPath);
  filterParts.push(`[${index}:a]adelay=${Math.round(clip.start * 1000)}:all=1[a${index}]`);
});
const labels = clipResults.map((_, index) => `[a${index}]`).join('');
filterParts.push(`${labels}amix=inputs=${clipResults.length}:normalize=0,apad,atrim=duration=${timeline.durationSeconds}[out]`);
await run('ffmpeg', ['-y', ...filterInputs, '-filter_complex', filterParts.join(';'), '-map', '[out]', '-ar', '48000', '-ac', '1', path.join(outputDir, 'narration.wav')]);

const vtt = ['WEBVTT', '', ...cues.flatMap((cue, index) => [String(index + 1), `${vttTimestamp(cue.start)} --> ${vttTimestamp(cue.end)}`, cue.text, ''])].join('\n');
await writeFile(path.join(outputDir, 'captions.vtt'), vtt);
await writeFile(path.join(outputDir, 'narration-manifest.json'), `${JSON.stringify({ voice, region, durationSeconds: timeline.durationSeconds, sections: clipResults.map(({ boundaries, clipPath, ...clip }) => ({ ...clip, clipPath: path.relative(root, clipPath) })) }, null, 2)}\n`);
console.log(`Narration synthesized with ${voice}: ${clipResults.length} sections, ${cues.length} caption cues.`);