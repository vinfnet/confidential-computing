export function resourcePrefix(value = 'demo') {
  if (typeof value !== 'string' || value !== value.trim() || !/^[a-z][a-z0-9]{0,7}$/.test(value)) {
    throw new Error('RESOURCE_PREFIX must be 1-8 lowercase letters/digits, starting with a letter.');
  }
  return value;
}

export function assertDeploymentOwner(recordedUpn, currentUpn, allowDifferentOwner = false) {
  if (typeof recordedUpn !== 'string' || !recordedUpn.trim() ||
      typeof currentUpn !== 'string' || !currentUpn.trim()) {
    throw new Error('Cannot verify deployment ownership without recorded and signed-in user identities.');
  }
  if (recordedUpn.toLowerCase() !== currentUpn.toLowerCase() && !allowDifferentOwner) {
    throw new Error('Unexpected deployment owner. Review identity before setting ALLOW_DIFFERENT_OWNER=1.');
  }
}
