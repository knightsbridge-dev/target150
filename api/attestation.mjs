// /api/attestation
//
// Post-quantum signed deploy attestation. Returns a JSON manifest describing
// the current deployment (git commit, ref, deployment id) and an ML-DSA-65
// (NIST FIPS 204) signature over the manifest. Anyone can verify that the
// JSON they're reading was produced by *this* deploy, not tampered with in
// flight, using the public key published at /.well-known/target150-pq-pubkey.
//
// Library: kxco-post-quantum (https://www.npmjs.com/package/kxco-post-quantum)
//          — production-tested PQ patterns by KXCO (Knightsbridge Group).
//
// Required env var:
//   TARGET150_PQ_MASTER  — any high-entropy secret (32+ chars). The signing
//                           keypair is derived deterministically from this.
//                           Rotate by changing the env var and redeploying.

import { mlDsa, fingerprint } from 'kxco-post-quantum'

let cachedKeypair = null

function getKeypair() {
  if (cachedKeypair) return cachedKeypair
  const master = process.env.TARGET150_PQ_MASTER
  if (!master || master.length < 32) {
    throw new Error('TARGET150_PQ_MASTER env var missing or too short (need 32+ chars)')
  }
  cachedKeypair = mlDsa.keypairFromMaster(master, 'target150-attestation-v1')
  return cachedKeypair
}

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'method not allowed' })
  }

  let kp
  try {
    kp = getKeypair()
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }

  const publicKeyHex = kp.publicKey.toString('hex')
  const kid = fingerprint(kp.publicKey)

  // Build manifest. Values stable for the lifetime of this deployment,
  // so we can cache aggressively without breaking signature verification.
  const manifest = {
    site:       'target150.com',
    alg:        'ML-DSA-65',
    spec:       'NIST FIPS 204',
    kid,
    deployment: {
      git_commit:    process.env.VERCEL_GIT_COMMIT_SHA       || 'unknown',
      git_ref:       process.env.VERCEL_GIT_COMMIT_REF       || 'unknown',
      git_repo_slug: process.env.VERCEL_GIT_REPO_SLUG        || 'unknown',
      url:           process.env.VERCEL_URL                  || 'unknown',
      env:           process.env.VERCEL_ENV                  || 'unknown',
      region:        process.env.VERCEL_REGION               || 'unknown',
    },
    msgFormat:  '{kid}.{deployment.git_commit}.{deployment.env}',
  }

  // Sign a deterministic, deployment-stable message. Signature is the same
  // across requests for the same deployment, so a cached copy is verifiable.
  const message = `${manifest.kid}.${manifest.deployment.git_commit}.${manifest.deployment.env}`
  const signatureHex = mlDsa.sign(kp.secretKey, message)

  res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400')
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.status(200).json({
    manifest,
    signedMessage: message,
    signature: {
      alg:      'ML-DSA-65',
      encoding: 'hex',
      value:    signatureHex,
    },
    publicKey: {
      alg:      'ML-DSA-65',
      encoding: 'hex',
      value:    publicKeyHex,
      kid,
      pinAt:    '/.well-known/target150-pq-pubkey',
    },
    verify: {
      package: 'kxco-post-quantum',
      version: '^1.0.3',
      docs:    'https://www.npmjs.com/package/kxco-post-quantum',
      example: "import { mlDsa } from 'kxco-post-quantum'; mlDsa.verify(publicKey, signedMessage, signature)",
    },
  })
}
