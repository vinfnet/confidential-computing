import { createHash } from 'node:crypto';

export function verifyPolicy(encoded, expectedContainers) {
  const bytes = Buffer.from(encoded, 'base64');
  const source = bytes.toString('utf8');
  const definition = /^containers\s*:=\s*(\[.*\])\s*$/m.exec(source);
  if (!/^package policy\s*$/m.test(source) || !definition) {
    throw new Error('Unrecognized generated CCE policy format');
  }
  const containers = JSON.parse(definition[1]);
  if (containers.length !== expectedContainers || containers.some(container =>
    container.allow_stdio_access !== false || container.allow_elevated !== false ||
    !Array.isArray(container.exec_processes) || container.exec_processes.length !== 0)) {
    throw new Error('CCE must deny stdio, elevation and exec for every measured container');
  }
  for (const setting of ['allow_dump_stacks', 'allow_runtime_logging']) {
    if (!new RegExp(`^${setting}\\s*:=\\s*false\\s*$`, 'm').test(source)) {
      throw new Error(`CCE must disable ${setting}`);
    }
  }
  return { source, hash: createHash('sha256').update(bytes).digest('hex') };
}
