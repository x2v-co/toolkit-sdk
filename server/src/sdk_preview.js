import { canonicalJson, digestObject } from './registry.js';
import {
  protocolCrossLanguageVectorPack,
  validateProtocolCrossLanguageVectorPack,
} from './protocol_fixtures.js';

export const SDK_PREVIEW_SCHEMA = 'toolkit.sdk-preview.v1';
export const SDK_SCAFFOLD_SCHEMA = 'toolkit.sdk.tool-scaffold.v1';
export const SDK_LOCKFILE_VERIFY_SCHEMA = 'toolkit.sdk.lockfile-verify.v1';
export const SDK_PUBLISH_DRY_RUN_SCHEMA = 'toolkit.sdk.publish-dry-run.v1';
export const SDK_BYOK_AGENT_SCHEMA = 'toolkit.sdk.byok-agent-request.v1';
export const SDK_BOOTSTRAP_INSTALL_SCHEMA = 'toolkit.sdk.bootstrap-install-preview.v1';

function slugify(value) {
  const slug = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!slug || !/^[a-z0-9][a-z0-9_-]{1,62}$/.test(slug)) throw new Error('SDK scaffold slug must be 2-63 chars of lowercase letters, digits, _ or -');
  return slug;
}

function safePath(path) {
  const value = String(path || '').trim();
  if (!value || value.startsWith('/') || value.includes('\\') || value.split('/').some((part) => part === '..')) {
    throw new Error('SDK scaffold file path must be safe and relative');
  }
  return value;
}

function assertSecretRef(value, label = 'secretRef') {
  const ref = String(value || '').trim();
  if (!ref) throw new Error(`${label} is required`);
  if (/^(sk_|pk_|AKIA|ASIA|bearer\s)/i.test(ref) || /token=|secret=|password=|api[_-]?key=/i.test(ref) || /[=\s]/.test(ref)) {
    throw new Error(`${label} must be an opaque secret reference, not raw credential material`);
  }
  return ref;
}

function withoutEnvelopeFields(value = {}) {
  const { digest: _digest, signature: _signature, ...payload } = value || {};
  return payload;
}

function isDigest(value) {
  return /^sha256:[0-9a-f]{64}$/.test(String(value || ''));
}

function trustMaterialDigest({ releaseTrust, registryTrust, verifier } = {}) {
  return digestObject({
    releaseTrust: releaseTrust || null,
    registryTrust: registryTrust || { state: 'disabled' },
    verifier: verifier || null,
  });
}

function isIndependentBootstrapChannel(channel = {}) {
  return channel.independentAdminDomain === true
    && channel.sameOriginAsDownload !== true
    && channel.sourceRepositorySelfFingerprint !== true
    && !['source-repository', 'same-origin-cdn', 'npm-scope'].includes(channel.channelType);
}

export function sdkBootstrapInstallPreview({
  packageName = 'toolkit-sdk',
  bootstrapTrust = {},
  authentication = {},
  channels = [],
  packageUpdate = {},
  persistedTrust = {},
} = {}) {
  const issues = [];
  const releaseTrust = bootstrapTrust.releaseTrust || {};
  const registryTrust = bootstrapTrust.registryTrust || { state: 'disabled' };
  const verifier = bootstrapTrust.verifier || {};
  const releaseRootVersion = Number(releaseTrust.rootVersion || 0);
  const releaseMinimumCheckpointVersion = Number(releaseTrust.minimumCheckpointVersion || 0);
  if (!releaseTrust.roots?.length) issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_ROOT_REQUIRED' });
  if (!Number.isSafeInteger(Number(releaseTrust.threshold)) || Number(releaseTrust.threshold) <= 0) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_THRESHOLD_INVALID' });
  }
  if (!Number.isSafeInteger(releaseRootVersion) || releaseRootVersion <= 0) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_ROOT_VERSION_INVALID' });
  }
  if (!Number.isSafeInteger(Number(releaseTrust.minimumPolicyVersion)) || Number(releaseTrust.minimumPolicyVersion) <= 0) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_MINIMUM_POLICY_VERSION_INVALID' });
  }
  if (!Number.isSafeInteger(releaseMinimumCheckpointVersion) || releaseMinimumCheckpointVersion <= 0) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_MINIMUM_CHECKPOINT_VERSION_INVALID' });
  }
  if (!isDigest(releaseTrust.minimumCheckpointDigest)) issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_MINIMUM_CHECKPOINT_REQUIRED' });
  if (persistedTrust.releaseRootVersion && releaseRootVersion < Number(persistedTrust.releaseRootVersion)) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_ROOT_VERSION_ROLLBACK' });
  }
  if (persistedTrust.releaseMinimumCheckpointVersion && releaseMinimumCheckpointVersion < Number(persistedTrust.releaseMinimumCheckpointVersion)) {
    issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_MINIMUM_CHECKPOINT_ROLLBACK' });
  }
  for (const root of releaseTrust.roots || []) {
    if (!root.kid || !isDigest(root.fingerprint)) issues.push({ code: 'SDK_BOOTSTRAP_RELEASE_ROOT_FINGERPRINT_INVALID' });
  }
  if (!verifier.identity || !isDigest(verifier.binaryDigest) || !isDigest(verifier.sourceDigest)) {
    issues.push({ code: 'SDK_BOOTSTRAP_VERIFIER_DIGEST_REQUIRED' });
  }
  if (registryTrust.state === 'enabled') {
    const registryRootVersion = Number(registryTrust.rootVersion || 0);
    const registryMinimumCheckpointVersion = Number(registryTrust.minimumCheckpointVersion || 0);
    if (!registryTrust.registryId) issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_ID_REQUIRED' });
    if (!registryTrust.roots?.length) issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_ROOT_REQUIRED' });
    if (!Number.isSafeInteger(registryRootVersion) || registryRootVersion <= 0) {
      issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_ROOT_VERSION_INVALID' });
    }
    if (!Number.isSafeInteger(registryMinimumCheckpointVersion) || registryMinimumCheckpointVersion <= 0) {
      issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_MINIMUM_CHECKPOINT_VERSION_INVALID' });
    }
    if (!isDigest(registryTrust.minimumCheckpointDigest)) issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_MINIMUM_CHECKPOINT_REQUIRED' });
    if (persistedTrust.registryRootVersion && registryRootVersion < Number(persistedTrust.registryRootVersion)) {
      issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_ROOT_VERSION_ROLLBACK' });
    }
    if (persistedTrust.registryMinimumCheckpointVersion && registryMinimumCheckpointVersion < Number(persistedTrust.registryMinimumCheckpointVersion)) {
      issues.push({ code: 'SDK_BOOTSTRAP_REGISTRY_MINIMUM_CHECKPOINT_ROLLBACK' });
    }
  }
  const bundleDigest = bootstrapTrust.digest || digestObject({
    releaseTrust,
    registryTrust,
    verifier,
  });
  if (bootstrapTrust.digest && !isDigest(bootstrapTrust.digest)) issues.push({ code: 'SDK_BOOTSTRAP_BUNDLE_DIGEST_INVALID' });
  if (packageUpdate.previousRegistryTrustState === 'disabled' && registryTrust.state === 'enabled'
    && packageUpdate.independentlyAuthenticatedRegistryTrust !== true) {
    issues.push({ code: 'SDK_PACKAGE_UPDATE_MAY_NOT_ENABLE_REGISTRY_TRUST' });
  }
  if (authentication.rootSignedChecksumOnly === true && authentication.rootFingerprintAuthenticated !== true) {
    issues.push({ code: 'SDK_ROOT_SIGNED_CHECKSUM_CANNOT_BOOTSTRAP' });
  }
  if (authentication.type === 'os-package-manager') {
    if (authentication.osSignatureValid !== true || !authentication.signerIdentity) {
      issues.push({ code: 'SDK_OS_PACKAGE_MANAGER_SIGNATURE_REQUIRED' });
    }
    if (authentication.bundleDigest && authentication.bundleDigest !== bundleDigest) {
      issues.push({ code: 'SDK_OS_PACKAGE_MANAGER_BUNDLE_DIGEST_MISMATCH' });
    }
  } else if (authentication.type === 'independent-channels') {
    const validChannels = (channels || []).filter(isIndependentBootstrapChannel);
    if (validChannels.length < 2) issues.push({ code: 'SDK_INDEPENDENT_BOOTSTRAP_CHANNELS_REQUIRED' });
    const adminDomains = new Set(validChannels.map((channel) => String(channel.adminDomain || channel.name || '').trim()).filter(Boolean));
    if (adminDomains.size < 2) issues.push({ code: 'SDK_INDEPENDENT_BOOTSTRAP_ADMIN_DOMAINS_REQUIRED' });
    const expectedMaterialDigest = trustMaterialDigest({ releaseTrust, registryTrust, verifier });
    for (const channel of validChannels) {
      if (channel.bundleDigest !== bundleDigest) issues.push({ code: 'SDK_BOOTSTRAP_CHANNEL_DIGEST_MISMATCH', channel: channel.name || '' });
      if (trustMaterialDigest(channel) !== expectedMaterialDigest) {
        issues.push({ code: 'SDK_BOOTSTRAP_CHANNEL_TRUST_MATERIAL_MISMATCH', channel: channel.name || '' });
      }
    }
  } else {
    issues.push({ code: 'SDK_BOOTSTRAP_AUTHENTICATION_METHOD_REQUIRED' });
  }
  const plan = {
    schemaVersion: SDK_BOOTSTRAP_INSTALL_SCHEMA,
    packageName: String(packageName || 'toolkit-sdk'),
    ok: issues.length === 0,
    issues,
    registryTrustState: registryTrust.state === 'enabled' ? 'enabled' : 'disabled',
    bundleDigest,
    networkEffect: 'none',
    previewOnly: true,
    highestTrustState: {
      releaseRootVersion,
      releaseMinimumCheckpointVersion,
      registryTrustState: registryTrust.state === 'enabled' ? 'enabled' : 'disabled',
      registryRootVersion: registryTrust.state === 'enabled' ? Number(registryTrust.rootVersion || 0) : 0,
      registryMinimumCheckpointVersion: registryTrust.state === 'enabled' ? Number(registryTrust.minimumCheckpointVersion || 0) : 0,
    },
  };
  plan.digest = digestObject(plan);
  return plan;
}

export function sdkScaffoldTool({
  slug,
  name,
  description = '',
  params = [],
  inputExample = 'hello',
} = {}) {
  const normalizedSlug = slugify(slug || name);
  const displayName = String(name || normalizedSlug).trim();
  if (!displayName) throw new Error('SDK scaffold name is required');
  const source = [
    'export async function transform(input, params = {}, ctx = {}) {',
    '  const text = String(input ?? "").trim();',
    '  return { ok: true, text, params };',
    '}',
    '',
  ].join('\n');
  const scaffold = {
    schemaVersion: SDK_SCAFFOLD_SCHEMA,
    packageName: 'toolkit-sdk',
    previewOnly: true,
    tool: {
      slug: normalizedSlug,
      name: displayName,
      description: String(description || '').trim(),
      params,
      inputExample,
    },
    files: [
      {
        path: 'src/index.js',
        mediaType: 'text/javascript; charset=utf-8',
        body: source,
      },
      {
        path: 'toolkit.tool.json',
        mediaType: 'application/json; charset=utf-8',
        body: canonicalJson({
          schemaVersion: 'toolkit.tool.source.v1',
          slug: normalizedSlug,
          name: displayName,
          description: String(description || '').trim(),
          entry: 'src/index.js',
          params,
          inputExample,
        }),
      },
    ],
    nextSteps: [
      'run local transform test',
      'run sdk publish dry-run',
      'submit manifest for registry governance review',
    ],
  };
  scaffold.digest = digestObject(scaffold);
  return scaffold;
}

export function validateSdkScaffold(scaffold = {}) {
  const issues = [];
  if (scaffold.schemaVersion !== SDK_SCAFFOLD_SCHEMA) issues.push({ code: 'SDK_SCAFFOLD_SCHEMA_MISMATCH' });
  if (scaffold.packageName !== 'toolkit-sdk') issues.push({ code: 'SDK_SCAFFOLD_PACKAGE_MISMATCH' });
  if (scaffold.previewOnly !== true) issues.push({ code: 'SDK_SCAFFOLD_PREVIEW_ONLY_REQUIRED' });
  try {
    slugify(scaffold.tool?.slug);
  } catch (error) {
    issues.push({ code: 'SDK_SCAFFOLD_SLUG_INVALID', message: error.message });
  }
  const files = Array.isArray(scaffold.files) ? scaffold.files : [];
  if (!files.length) issues.push({ code: 'SDK_SCAFFOLD_FILES_REQUIRED' });
  const paths = new Set();
  for (const file of files) {
    try {
      const path = safePath(file.path);
      if (paths.has(path)) issues.push({ code: 'SDK_SCAFFOLD_DUPLICATE_PATH', path });
      paths.add(path);
    } catch (error) {
      issues.push({ code: 'SDK_SCAFFOLD_PATH_INVALID', message: error.message });
    }
    const body = String(file.body || '');
    if (/sk_live_|AKIA|BEGIN PRIVATE KEY|password\s*=|api[_-]?key\s*=/i.test(body)) {
      issues.push({ code: 'SDK_SCAFFOLD_SECRET_LEAK', path: file.path || '' });
    }
  }
  if (!files.some((file) => file.path === 'src/index.js' && String(file.body || '').includes('function transform'))) {
    issues.push({ code: 'SDK_SCAFFOLD_TRANSFORM_ENTRY_MISSING' });
  }
  if (scaffold.digest !== digestObject(withoutEnvelopeFields(scaffold))) issues.push({ code: 'SDK_SCAFFOLD_DIGEST_MISMATCH' });
  return { ok: issues.length === 0, issues };
}

export function sdkVerifyLockfileResolutionCore({ resolutionCore, vectorPack = protocolCrossLanguageVectorPack() } = {}) {
  const issues = [];
  const vectorValidation = validateProtocolCrossLanguageVectorPack(vectorPack);
  if (vectorValidation.ok !== true) issues.push({ code: 'SDK_PROTOCOL_VECTOR_INVALID' });
  if (resolutionCore?.schemaVersion !== 'toolkit.lock.resolution.v1') issues.push({ code: 'SDK_LOCKFILE_SCHEMA_MISMATCH' });
  const expectedDigest = resolutionCore ? digestObject(withoutEnvelopeFields(resolutionCore)) : '';
  if (!resolutionCore?.digest || resolutionCore.digest !== expectedDigest) {
    issues.push({ code: 'SDK_LOCKFILE_DIGEST_MISMATCH', expectedDigest });
  }
  if (!resolutionCore?.signature?.payloadDigest || resolutionCore.signature.payloadDigest !== resolutionCore?.digest) {
    issues.push({ code: 'SDK_LOCKFILE_SIGNATURE_PAYLOAD_MISMATCH' });
  }
  if (!resolutionCore?.statusPolicy || resolutionCore.statusPolicy.executionProofMaxAgeSeconds !== 300) {
    issues.push({ code: 'SDK_LOCKFILE_STATUS_POLICY_MISMATCH' });
  }
  for (const tool of resolutionCore?.tools || []) {
    if (!tool.manifest?.digest || !tool.artifact?.digest) {
      issues.push({ code: 'SDK_LOCKFILE_TOOL_DIGEST_MISSING', slug: tool.slug || '' });
    }
  }
  const result = {
    schemaVersion: SDK_LOCKFILE_VERIFY_SCHEMA,
    ok: issues.length === 0,
    issues,
    lockfileDigest: resolutionCore?.digest || '',
    vectorSchemaVersion: vectorPack.schemaVersion || '',
    vectorCount: (vectorPack.vectors || []).length,
  };
  result.digest = digestObject(result);
  return result;
}

export function sdkPublishDryRun({
  scaffold,
  registryBaseUrl = 'https://toolkit.fun',
  registryTrust = { enabled: false },
  rightsAttestation = {},
} = {}) {
  const scaffoldValidation = validateSdkScaffold(scaffold);
  const issues = [...scaffoldValidation.issues];
  if (registryTrust?.enabled === true) issues.push({ code: 'SDK_DRY_RUN_REGISTRY_TRUST_MUST_STAY_DISABLED' });
  if (rightsAttestation.publisherAcceptedTerms !== true) issues.push({ code: 'SDK_DRY_RUN_RIGHTS_ATTESTATION_REQUIRED' });
  if (!String(registryBaseUrl || '').startsWith('https://')) issues.push({ code: 'SDK_DRY_RUN_REGISTRY_URL_HTTPS_REQUIRED' });
  const plan = {
    schemaVersion: SDK_PUBLISH_DRY_RUN_SCHEMA,
    ok: issues.length === 0,
    issues,
    networkEffect: 'none',
    previewOnly: true,
    registryBaseUrl: String(registryBaseUrl || ''),
    tool: {
      slug: scaffold?.tool?.slug || '',
      name: scaffold?.tool?.name || '',
    },
    scaffoldDigest: scaffold?.digest || '',
    requiredReview: [
      'registry governance approval',
      'license scan',
      'secret scan',
      'malware scan',
    ],
  };
  plan.digest = digestObject(plan);
  return plan;
}

export function sdkByokAgentRequest({
  prompt,
  provider = 'openai-compatible',
  model = 'user-selected',
  secretRef,
  operationId = 'sdk-byok-preview',
} = {}) {
  const request = {
    schemaVersion: SDK_BYOK_AGENT_SCHEMA,
    provider: String(provider || 'openai-compatible'),
    model: String(model || 'user-selected'),
    promptPreview: String(prompt || '').slice(0, 120),
    promptDigest: digestObject({ prompt: String(prompt || '') }),
    secretRef: assertSecretRef(secretRef, 'BYOK secretRef'),
    operationId: String(operationId || 'sdk-byok-preview'),
    billableToPlatform: false,
    sendsRawSecretToToolkit: false,
  };
  request.digest = digestObject(request);
  return request;
}

export function sdkPreviewManifest() {
  return {
    schemaVersion: SDK_PREVIEW_SCHEMA,
    packageName: 'toolkit-sdk',
    status: 'developer-preview',
    capabilities: [
      'sdk-scaffold-tool',
      'sdk-verify-lockfile',
      'sdk-publish-dry-run',
      'sdk-byok-agent',
      'sdk-bootstrap-trust',
    ],
    registryTrustDefault: 'disabled',
    networkPublishing: 'dry-run-only',
  };
}
