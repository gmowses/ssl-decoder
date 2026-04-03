import { useState } from 'react'
import { ShieldCheck, Sun, Moon, Languages, Copy, Check, FileKey, AlertTriangle } from 'lucide-react'

// ── i18n ─────────────────────────────────────────────────────────────────────
const translations = {
  en: {
    title: 'SSL Certificate Decoder',
    subtitle: 'Paste a PEM certificate to decode its fields. Everything runs client-side — no data is sent to any server.',
    inputLabel: 'PEM Certificate',
    inputPlaceholder: '-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----',
    decode: 'Decode',
    clear: 'Clear',
    copy: 'Copy',
    copied: 'Copied!',
    result: 'Certificate Details',
    subject: 'Subject',
    issuer: 'Issuer',
    serial: 'Serial Number',
    validity: 'Validity',
    notBefore: 'Not Before',
    notAfter: 'Not After',
    expired: 'EXPIRED',
    valid: 'VALID',
    daysLeft: 'days left',
    daysAgo: 'days ago',
    sans: 'Subject Alternative Names',
    keyAlgorithm: 'Key Algorithm',
    keySize: 'Key Size',
    sigAlgorithm: 'Signature Algorithm',
    fingerprints: 'Fingerprints',
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    version: 'Version',
    basicConstraints: 'Basic Constraints',
    keyUsage: 'Key Usage',
    extKeyUsage: 'Extended Key Usage',
    errorEmpty: 'Paste a PEM certificate to decode.',
    errorInvalid: 'Could not parse the certificate. Make sure it is a valid PEM-encoded X.509 certificate.',
    errorNoBrowser: 'Your browser does not support the Web Crypto API required for fingerprint computation.',
    builtBy: 'Built by',
    cn: 'CN',
    o: 'O',
    ou: 'OU',
    l: 'L',
    st: 'ST',
    c: 'C',
    bits: 'bits',
    ca: 'CA',
    notCA: 'End-entity',
    pathLen: 'Path Length',
    unlimited: 'Unlimited',
    selfSigned: 'Self-signed',
    computingFingerprints: 'Computing...',
  },
  pt: {
    title: 'Decodificador de Certificado SSL',
    subtitle: 'Cole um certificado PEM para decodificar seus campos. Tudo roda no navegador — nenhum dado e enviado ao servidor.',
    inputLabel: 'Certificado PEM',
    inputPlaceholder: '-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----',
    decode: 'Decodificar',
    clear: 'Limpar',
    copy: 'Copiar',
    copied: 'Copiado!',
    result: 'Detalhes do Certificado',
    subject: 'Titular',
    issuer: 'Emissor',
    serial: 'Numero de Serie',
    validity: 'Validade',
    notBefore: 'Valido a partir de',
    notAfter: 'Valido ate',
    expired: 'EXPIRADO',
    valid: 'VALIDO',
    daysLeft: 'dias restantes',
    daysAgo: 'dias atras',
    sans: 'Nomes Alternativos (SANs)',
    keyAlgorithm: 'Algoritmo da Chave',
    keySize: 'Tamanho da Chave',
    sigAlgorithm: 'Algoritmo de Assinatura',
    fingerprints: 'Impressoes Digitais',
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    version: 'Versao',
    basicConstraints: 'Restricoes Basicas',
    keyUsage: 'Uso da Chave',
    extKeyUsage: 'Uso Estendido da Chave',
    errorEmpty: 'Cole um certificado PEM para decodificar.',
    errorInvalid: 'Nao foi possivel analisar o certificado. Verifique se e um certificado X.509 valido no formato PEM.',
    errorNoBrowser: 'Seu navegador nao suporta a Web Crypto API necessaria para calcular impressoes digitais.',
    builtBy: 'Criado por',
    cn: 'CN',
    o: 'O',
    ou: 'OU',
    l: 'L',
    st: 'ST',
    c: 'C',
    bits: 'bits',
    ca: 'CA',
    notCA: 'Entidade final',
    pathLen: 'Comprimento do caminho',
    unlimited: 'Ilimitado',
    selfSigned: 'Auto-assinado',
    computingFingerprints: 'Calculando...',
  },
} as const
type Lang = keyof typeof translations

// ── ASN.1 / DER parsing ───────────────────────────────────────────────────────
// Minimal DER parser — handles the fields we care about in X.509v3 certs

interface DerNode {
  tag: number
  constructed: boolean
  bytes: Uint8Array
  children?: DerNode[]
}

function parseDer(buf: Uint8Array, offset = 0): { node: DerNode; end: number } {
  const tag = buf[offset]
  const constructed = (tag & 0x20) !== 0
  let lenByte = buf[offset + 1]
  let dataStart = offset + 2
  let length: number
  if (lenByte < 0x80) {
    length = lenByte
  } else {
    const numBytes = lenByte & 0x7f
    length = 0
    for (let i = 0; i < numBytes; i++) length = (length << 8) | buf[dataStart++]
  }
  const bytes = buf.slice(dataStart, dataStart + length)
  const node: DerNode = { tag, constructed, bytes }
  if (constructed) {
    node.children = []
    let pos = 0
    while (pos < bytes.length) {
      const { node: child, end } = parseDer(bytes, pos)
      node.children.push(child)
      pos = end
    }
  }
  return { node, end: dataStart + length - offset }
}

function parseAll(buf: Uint8Array): DerNode {
  return parseDer(buf).node
}

// OID map (subset relevant to certs)
const OID_MAP: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber',
  '2.5.4.12': 'title',
  '2.5.4.42': 'givenName',
  '2.5.4.4': 'surname',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.3.1.7': 'secp256r1 (P-256)',
  '1.3.132.0.34': 'secp384r1 (P-384)',
  '1.3.132.0.35': 'secp521r1 (P-521)',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.15': 'keyUsage',
  '2.5.29.37': 'extKeyUsage',
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  '1.2.840.113549.1.9.14': 'extensionRequest',
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) return ''
  const parts: number[] = []
  parts.push(Math.floor(bytes[0] / 40))
  parts.push(bytes[0] % 40)
  let cur = 0
  for (let i = 1; i < bytes.length; i++) {
    cur = (cur << 7) | (bytes[i] & 0x7f)
    if ((bytes[i] & 0x80) === 0) { parts.push(cur); cur = 0 }
  }
  const oid = parts.join('.')
  return OID_MAP[oid] ?? oid
}

function decodeUtf8(bytes: Uint8Array): string {
  try { return new TextDecoder().decode(bytes) } catch { return '' }
}

function decodeDate(bytes: Uint8Array, tag: number): Date {
  const s = decodeUtf8(bytes)
  // UTCTime: YYMMDDHHMMSSZ, GeneralizedTime: YYYYMMDDHHMMSSZ
  if (tag === 0x17) {
    // UTCTime
    const yr = parseInt(s.slice(0, 2))
    const year = yr >= 50 ? 1900 + yr : 2000 + yr
    return new Date(`${year}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`)
  }
  return new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`)
}

function parseRdn(seq: DerNode): Record<string, string> {
  const result: Record<string, string> = {}
  for (const set of seq.children ?? []) {
    for (const atv of set.children ?? []) {
      const children = atv.children ?? []
      if (children.length >= 2) {
        const key = decodeOid(children[0].bytes)
        const val = decodeUtf8(children[1].bytes)
        result[key] = val
      }
    }
  }
  return result
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase()
}

function bigintHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

interface ParsedSans {
  dns: string[]
  ip: string[]
  email: string[]
  uri: string[]
}

function parseSANExtension(extValueBytes: Uint8Array): ParsedSans {
  const result: ParsedSans = { dns: [], ip: [], email: [], uri: [] }
  try {
    const outer = parseAll(extValueBytes)
    const seq = outer.tag === 0x04 ? parseAll(outer.bytes) : outer
    for (const name of seq.children ?? []) {
      const tagType = name.tag & 0x1f
      const val = decodeUtf8(name.bytes)
      if (tagType === 2) result.dns.push(val)
      else if (tagType === 7) {
        if (name.bytes.length === 4) result.ip.push(Array.from(name.bytes).join('.'))
        else if (name.bytes.length === 16) {
          const parts: string[] = []
          for (let i = 0; i < 16; i += 2) parts.push(((name.bytes[i] << 8) | name.bytes[i + 1]).toString(16))
          result.ip.push(parts.join(':'))
        }
      } else if (tagType === 1) result.email.push(val)
      else if (tagType === 6) result.uri.push(val)
    }
  } catch { /* ignore parse errors */ }
  return result
}

function parseKeyUsage(bytes: Uint8Array): string[] {
  const names = ['digitalSignature','nonRepudiation','keyEncipherment','dataEncipherment','keyAgreement','keyCertSign','cRLSign','encipherOnly','decipherOnly']
  if (bytes.length < 2) return []
  // bytes[0] = unused bits count, bytes[1] = bit string byte
  const _unused = bytes[0]
  void _unused
  const result: string[] = []
  for (let i = 0; i < 9; i++) {
    const bitIdx = 7 - ((i) % 8)
    const byteval = i < 8 ? bytes[1] : (bytes.length > 2 ? bytes[2] : 0)
    if ((byteval >> bitIdx) & 1) result.push(names[i])
  }
  return result
}

function parseExtKeyUsage(outerBytes: Uint8Array): string[] {
  try {
    const outer = parseAll(outerBytes)
    const seq = outer.tag === 0x04 ? parseAll(outer.bytes) : outer
    return (seq.children ?? []).map(c => decodeOid(c.bytes))
  } catch { return [] }
}

interface CertInfo {
  version: number
  serial: string
  subject: Record<string, string>
  issuer: Record<string, string>
  notBefore: Date
  notAfter: Date
  keyAlgorithm: string
  keySize: number | null
  sigAlgorithm: string
  sans: ParsedSans
  isCA: boolean | null
  pathLen: number | null
  keyUsage: string[]
  extKeyUsage: string[]
  sha1: string
  sha256: string
  selfSigned: boolean
  rawBytes: Uint8Array
}

async function parsePem(pem: string): Promise<CertInfo> {
  const stripped = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '')
  const binaryStr = atob(stripped)
  const bytes = Uint8Array.from(binaryStr, c => c.charCodeAt(0))

  const root = parseAll(bytes)
  // root = SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  const tbsCert = root.children?.[0]
  const sigAlgNode = root.children?.[1]
  if (!tbsCert || !tbsCert.children) throw new Error('invalid')

  let idx = 0
  // version is optional [0] EXPLICIT
  let version = 1
  if ((tbsCert.children[idx].tag & 0x1f) === 0 && tbsCert.children[idx].constructed) {
    version = (tbsCert.children[idx].children?.[0]?.bytes[0] ?? 0) + 1
    idx++
  }
  const serialNode = tbsCert.children[idx++]
  const serial = bigintHex(serialNode.bytes)

  const _sigAlgInTbs = tbsCert.children[idx++]
  void _sigAlgInTbs

  const issuerNode = tbsCert.children[idx++]
  const issuer = parseRdn(issuerNode)

  const validityNode = tbsCert.children[idx++]
  const notBefore = decodeDate(validityNode.children![0].bytes, validityNode.children![0].tag)
  const notAfter = decodeDate(validityNode.children![1].bytes, validityNode.children![1].tag)

  const subjectNode = tbsCert.children[idx++]
  const subject = parseRdn(subjectNode)

  const spkiNode = tbsCert.children[idx++]
  let keyAlgorithm = ''
  let keySize: number | null = null
  if (spkiNode.children) {
    const algId = spkiNode.children[0]
    if (algId.children) keyAlgorithm = decodeOid(algId.children[0].bytes)
    // RSA: BitString -> SEQUENCE { INTEGER modulus, INTEGER exp }
    if (keyAlgorithm === 'rsaEncryption' && spkiNode.children[1]) {
      try {
        const bitStr = spkiNode.children[1].bytes
        const rsaSeq = parseAll(bitStr.slice(1)) // skip unused bits byte
        const modulus = rsaSeq.children?.[0]?.bytes ?? new Uint8Array()
        // leading 00 byte is sign padding
        const effectiveLen = modulus[0] === 0 ? modulus.length - 1 : modulus.length
        keySize = effectiveLen * 8
      } catch { /* ignore */ }
    }
    // EC: curve OID is in algId
    if (keyAlgorithm === 'ecPublicKey' && algId.children?.[1]) {
      const curveOid = decodeOid(algId.children[1].bytes)
      keyAlgorithm = `ecPublicKey (${curveOid})`
      // derive key size from curve
      if (curveOid.includes('P-256') || curveOid.includes('secp256r1')) keySize = 256
      else if (curveOid.includes('P-384') || curveOid.includes('secp384r1')) keySize = 384
      else if (curveOid.includes('P-521') || curveOid.includes('secp521r1')) keySize = 521
    }
  }

  // sigAlgorithm from outer
  let sigAlgorithm = ''
  if (sigAlgNode?.children) sigAlgorithm = decodeOid(sigAlgNode.children[0].bytes)

  // Extensions (v3 only)
  let sans: ParsedSans = { dns: [], ip: [], email: [], uri: [] }
  let isCA: boolean | null = null
  let pathLen: number | null = null
  let keyUsage: string[] = []
  let extKeyUsage: string[] = []

  // Skip issuerUniqueID [1] and subjectUniqueID [2] if present
  while (idx < tbsCert.children.length && !tbsCert.children[idx].constructed && (tbsCert.children[idx].tag & 0x20) === 0) idx++

  if (version === 3 && idx < tbsCert.children.length) {
    const extsWrapper = tbsCert.children[idx]
    const exts = extsWrapper.children?.[0]
    for (const ext of exts?.children ?? []) {
      if (!ext.children) continue
      const oidBytes = ext.children[0].bytes
      const oidStr = decodeOid(oidBytes)
      // value is last child (critical BOOLEAN may be second)
      const valueNode = ext.children[ext.children.length - 1]
      if (oidStr === 'subjectAltName') {
        sans = parseSANExtension(valueNode.bytes)
      } else if (oidStr === 'basicConstraints') {
        try {
          const inner = parseAll(valueNode.bytes)
          const seq = inner.tag === 0x04 ? parseAll(inner.bytes) : inner
          if (seq.children?.[0]) isCA = seq.children[0].bytes[0] !== 0
          if (seq.children?.[1]) pathLen = seq.children[1].bytes[0]
          else if (isCA) pathLen = null
        } catch { /* ignore */ }
      } else if (oidStr === 'keyUsage') {
        try {
          const inner = parseAll(valueNode.bytes)
          const bitStr = inner.tag === 0x04 ? parseAll(inner.bytes).bytes : inner.bytes
          keyUsage = parseKeyUsage(bitStr)
        } catch { /* ignore */ }
      } else if (oidStr === 'extKeyUsage') {
        extKeyUsage = parseExtKeyUsage(valueNode.bytes)
      }
    }
  }

  // Fingerprints
  const sha1Buf = await crypto.subtle.digest('SHA-1', bytes)
  const sha256Buf = await crypto.subtle.digest('SHA-256', bytes)
  const sha1 = hexOf(new Uint8Array(sha1Buf))
  const sha256Hex = hexOf(new Uint8Array(sha256Buf))

  const selfSigned = JSON.stringify(subject) === JSON.stringify(issuer)

  return {
    version, serial, subject, issuer, notBefore, notAfter,
    keyAlgorithm, keySize, sigAlgorithm, sans,
    isCA, pathLen, keyUsage, extKeyUsage,
    sha1, sha256: sha256Hex, selfSigned, rawBytes: bytes,
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function rdnLine(rdn: Record<string, string>): string {
  const order = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'emailAddress', 'serialNumber']
  const parts: string[] = []
  for (const k of order) if (rdn[k]) parts.push(`${k}=${rdn[k]}`)
  for (const k of Object.keys(rdn)) if (!order.includes(k) && rdn[k]) parts.push(`${k}=${rdn[k]}`)
  return parts.join(', ')
}

function daysUntil(d: Date): number {
  return Math.ceil((d.getTime() - Date.now()) / 86400000)
}

interface FieldProps { label: string; value: string; mono?: boolean; accent?: string }
function Field({ label, value, mono = false, accent }: FieldProps) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }
  return (
    <div className="group rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/30 px-3 py-2.5">
      <div className="flex items-center justify-between mb-0.5">
        <p className={`text-[10px] uppercase tracking-wide font-semibold ${accent ?? 'text-zinc-400'}`}>{label}</p>
        <button onClick={copy} className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200">
          {copied ? <Check size={11} /> : <Copy size={11} />}
        </button>
      </div>
      <p className={`text-sm break-all ${mono ? 'font-mono text-xs' : 'font-medium'}`}>{value}</p>
    </div>
  )
}

function Badge({ children, color }: { children: React.ReactNode; color: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${color}`}>{children}</span>
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SslDecoder() {
  const [lang, setLang] = useState<Lang>(() => navigator.language.startsWith('pt') ? 'pt' : 'en')
  const [dark, setDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches)
  const [pem, setPem] = useState('')
  const [cert, setCert] = useState<CertInfo | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const t = translations[lang]

  const toggleDark = () => {
    const next = !dark
    setDark(next)
    document.documentElement.classList.toggle('dark', next)
  }
  // sync dark on mount
  useState(() => { document.documentElement.classList.toggle('dark', dark) })

  const handleDecode = async () => {
    if (!pem.trim()) { setError(t.errorEmpty); return }
    setError('')
    setLoading(true)
    try {
      const info = await parsePem(pem)
      setCert(info)
    } catch {
      setError(t.errorInvalid)
      setCert(null)
    } finally {
      setLoading(false)
    }
  }

  const handleClear = () => { setPem(''); setCert(null); setError('') }

  const days = cert ? daysUntil(cert.notAfter) : 0
  const isExpired = cert ? days < 0 : false

  return (
    <div className="min-h-screen flex flex-col bg-white dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 transition-colors">
      {/* Header */}
      <header className="border-b border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-green-500 rounded-lg flex items-center justify-center">
              <FileKey size={18} className="text-white" />
            </div>
            <span className="font-semibold">SSL Decoder</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setLang(l => l === 'en' ? 'pt' : 'en')} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <Languages size={14} />{lang.toUpperCase()}
            </button>
            <button onClick={toggleDark} className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <a href="https://github.com/gmowses/ssl-decoder" target="_blank" rel="noopener noreferrer" className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            </a>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 px-6 py-10">
        <div className="max-w-5xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold">{t.title}</h1>
            <p className="mt-2 text-zinc-500 dark:text-zinc-400">{t.subtitle}</p>
          </div>

          {/* Input */}
          <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4">
            <label className="block text-sm font-medium">{t.inputLabel}</label>
            <textarea
              value={pem}
              onChange={e => setPem(e.target.value)}
              rows={8}
              placeholder={t.inputPlaceholder}
              spellCheck={false}
              className="w-full rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 px-4 py-3 font-mono text-xs resize-y focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors placeholder:text-zinc-400"
            />
            {error && (
              <div className="flex items-start gap-2 rounded-md border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 px-3 py-2 text-xs text-red-600 dark:text-red-400">
                <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                {error}
              </div>
            )}
            <div className="flex gap-3">
              <button onClick={handleDecode} disabled={loading} className="flex items-center gap-2 rounded-lg bg-green-500 px-5 py-2.5 text-sm font-medium text-white hover:bg-green-600 transition-colors disabled:opacity-60">
                <ShieldCheck size={15} />
                {loading ? '...' : t.decode}
              </button>
              <button onClick={handleClear} className="rounded-lg border border-zinc-200 dark:border-zinc-700 px-4 py-2.5 text-sm font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
                {t.clear}
              </button>
            </div>
          </div>

          {/* Results */}
          {cert && (
            <div className="space-y-6">
              {/* Validity banner */}
              <div className={`rounded-xl border px-5 py-4 flex items-center justify-between ${isExpired ? 'border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20' : 'border-green-300 dark:border-green-800 bg-green-50 dark:bg-green-900/20'}`}>
                <div className="flex items-center gap-3">
                  <ShieldCheck size={20} className={isExpired ? 'text-red-500' : 'text-green-500'} />
                  <div>
                    <p className="font-semibold text-sm">{cert.subject['CN'] ?? rdnLine(cert.subject)}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">{cert.issuer['O'] ?? cert.issuer['CN'] ?? rdnLine(cert.issuer)}</p>
                  </div>
                </div>
                <div className="text-right">
                  <Badge color={isExpired ? 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400' : 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400'}>
                    {isExpired ? t.expired : t.valid}
                  </Badge>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                    {Math.abs(days)} {isExpired ? t.daysAgo : t.daysLeft}
                  </p>
                </div>
              </div>

              <div className="grid gap-6 lg:grid-cols-2">
                {/* Identity */}
                <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                  <h2 className="font-semibold text-green-500">{t.subject}</h2>
                  {Object.entries(cert.subject).map(([k, v]) => (
                    <Field key={k} label={k} value={v} />
                  ))}
                  {cert.selfSigned && (
                    <Badge color="bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-400">{t.selfSigned}</Badge>
                  )}
                </div>

                <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                  <h2 className="font-semibold text-green-500">{t.issuer}</h2>
                  {Object.entries(cert.issuer).map(([k, v]) => (
                    <Field key={k} label={k} value={v} />
                  ))}
                </div>
              </div>

              {/* Validity */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                <h2 className="font-semibold text-green-500">{t.validity}</h2>
                <div className="grid gap-3 sm:grid-cols-3">
                  <Field label={t.version} value={`v${cert.version}`} />
                  <Field label={t.notBefore} value={cert.notBefore.toUTCString()} />
                  <Field label={t.notAfter} value={cert.notAfter.toUTCString()} accent={isExpired ? 'text-red-500' : 'text-green-500'} />
                </div>
              </div>

              {/* Key info */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                <h2 className="font-semibold text-green-500">{t.keyAlgorithm} / {t.sigAlgorithm}</h2>
                <div className="grid gap-3 sm:grid-cols-3">
                  <Field label={t.keyAlgorithm} value={cert.keyAlgorithm || '—'} />
                  {cert.keySize !== null && <Field label={t.keySize} value={`${cert.keySize} ${t.bits}`} />}
                  <Field label={t.sigAlgorithm} value={cert.sigAlgorithm || '—'} />
                  <Field label={t.serial} value={cert.serial} mono />
                  <Field label={t.basicConstraints} value={
                    cert.isCA === null ? '—' :
                    cert.isCA ? `${t.ca} — ${t.pathLen}: ${cert.pathLen === null ? t.unlimited : cert.pathLen}` : t.notCA
                  } />
                </div>
              </div>

              {/* SANs */}
              {(cert.sans.dns.length > 0 || cert.sans.ip.length > 0 || cert.sans.email.length > 0 || cert.sans.uri.length > 0) && (
                <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                  <h2 className="font-semibold text-green-500">{t.sans}</h2>
                  <div className="flex flex-wrap gap-2">
                    {cert.sans.dns.map(s => <Badge key={s} color="bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400">DNS: {s}</Badge>)}
                    {cert.sans.ip.map(s => <Badge key={s} color="bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400">IP: {s}</Badge>)}
                    {cert.sans.email.map(s => <Badge key={s} color="bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-400">email: {s}</Badge>)}
                    {cert.sans.uri.map(s => <Badge key={s} color="bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-400">URI: {s}</Badge>)}
                  </div>
                </div>
              )}

              {/* Key usage */}
              {(cert.keyUsage.length > 0 || cert.extKeyUsage.length > 0) && (
                <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                  <h2 className="font-semibold text-green-500">{t.keyUsage} / {t.extKeyUsage}</h2>
                  {cert.keyUsage.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-zinc-400 mb-2">{t.keyUsage}</p>
                      <div className="flex flex-wrap gap-2">
                        {cert.keyUsage.map(u => <Badge key={u} color="bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">{u}</Badge>)}
                      </div>
                    </div>
                  )}
                  {cert.extKeyUsage.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-zinc-400 mb-2">{t.extKeyUsage}</p>
                      <div className="flex flex-wrap gap-2">
                        {cert.extKeyUsage.map(u => <Badge key={u} color="bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">{u}</Badge>)}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Fingerprints */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-3">
                <h2 className="font-semibold text-green-500">{t.fingerprints}</h2>
                <Field label={t.sha1} value={cert.sha1} mono />
                <Field label={t.sha256} value={cert.sha256} mono />
              </div>
            </div>
          )}
        </div>
      </main>

      <footer className="border-t border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-xs text-zinc-400">
          <span>{t.builtBy} <a href="https://github.com/gmowses" className="text-zinc-600 dark:text-zinc-300 hover:text-green-500 transition-colors">Gabriel Mowses</a></span>
          <span>MIT License</span>
        </div>
      </footer>
    </div>
  )
}
