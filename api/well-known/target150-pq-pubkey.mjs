// /.well-known/target150-pq-pubkey  (via vercel.json rewrite)
//
// Public discovery endpoint for the site's ML-DSA-65 signing key.
// Verifiers fetch this once, pin the key by its kid (fingerprint), and verify
// attestations and any signed responses against it.
//
// Stable for the lifetime of TARGET150_PQ_MASTER. Rotate the env var to
// rotate the key; verifiers will see a new kid and re-pin.
//
// Library: kxco-post-quantum (https://www.npmjs.com/package/kxco-post-quantum)

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

  res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=604800')
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.status(200).json({
    site:      'target150.com',
    alg:       'ML-DSA-65',
    spec:      'NIST FIPS 204',
    publicKey: kp.publicKey.toString('hex'),
    kid:       fingerprint(kp.publicKey),
    sigEncoding: 'hex',
    attestationEndpoint: '/api/attestation',
    library: {
      name: 'kxco-post-quantum',
      docs: 'https://www.npmjs.com/package/kxco-post-quantum',
    },
  })
}
