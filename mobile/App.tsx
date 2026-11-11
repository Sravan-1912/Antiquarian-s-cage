import { useCallback, useEffect, useRef, useState } from 'react'
import { ActivityIndicator, Alert, AppState, Platform, Pressable, SafeAreaView, ScrollView, StyleSheet, Text, View } from 'react-native'
import { StatusBar } from 'expo-status-bar'
import { CameraView, useCameraPermissions } from 'expo-camera'
import * as Device from 'expo-device'
import {
  type Account, type PendingRequest, biometricAvailable, checkServer, decide, fetchPending, forgetAccount, loadAccounts,
  pair, parsePairingCode,
} from './src/core'

const C = {
  bg: '#050806', card: '#0b120d', line: '#1a2a1e', green: '#3ddc6e', greenDim: '#1f7a3e', text: '#e9f5ec',
  mute: '#8aa393', red: '#ff6b6b', amber: '#f5b942',
}

type Screen = { name: 'home' } | { name: 'scan' } | { name: 'request'; req: PendingRequest } |
  { name: 'done'; ok: boolean; title: string; detail: string }

export default function App() {
  const [screen, setScreen] = useState<Screen>({ name: 'home' })
  const [accounts, setAccounts] = useState<Account[]>([])
  const [bio, setBio] = useState<{ ok: boolean; kind: string | null; reason?: string } | null>(null)
  const [status, setStatus] = useState<string | null>(null)
  const shown = useRef(new Set<string>())

  const refreshAccounts = useCallback(async () => setAccounts(await loadAccounts()), [])
  useEffect(() => { void refreshAccounts(); void biometricAvailable().then(setBio) }, [refreshAccounts])

  // Poll for approval requests while the app is open and on the home screen.
  useEffect(() => {
    if (screen.name !== 'home' || accounts.length === 0) return
    let active = AppState.currentState === 'active'
    const sub = AppState.addEventListener('change', (s) => { active = s === 'active' })
    const tick = async () => {
      if (!active) return
      const r = await fetchPending(accounts)
      for (const a of r.revoked) await forgetAccount(a)
      if (r.revoked.length) {
        await refreshAccounts()
        Alert.alert('Account removed', `${r.revoked.map((a) => a.account).join(', ')} no longer accepts this phone. Pair again from the console if needed.`)
      }
      setStatus(r.errors.length ? `Cannot reach server: ${r.errors[0]}` : null)
      const next = r.requests.find((x) => !shown.current.has(x.id))
      if (next) { shown.current.add(next.id); setScreen({ name: 'request', req: next }) }
    }
    void tick()
    const t = setInterval(tick, 3000)
    return () => { clearInterval(t); sub.remove() }
  }, [screen.name, accounts, refreshAccounts])

  return (
    <SafeAreaView style={s.root}>
      <StatusBar style="light" />
      <View style={s.header}>
        <Text style={s.brand}>CAGE <Text style={{ color: C.green }}>AUTHENTICATOR</Text></Text>
        <Text style={s.shield}>◈</Text>
      </View>
      {screen.name === 'home' && (
        <Home accounts={accounts} bio={bio} status={status} onPair={() => setScreen({ name: 'scan' })}
          onForget={async (a) => { await forgetAccount(a); await refreshAccounts() }} />
      )}
      {screen.name === 'scan' && (
        <Scan onCancel={() => setScreen({ name: 'home' })}
          onPaired={async (a) => { await refreshAccounts(); setScreen({ name: 'done', ok: true, title: 'Phone paired', detail: `${a.account} can now sign in by approving on this phone.` }) }}
          onError={(msg) => setScreen({ name: 'done', ok: false, title: 'Pairing failed', detail: msg })} />
      )}
      {screen.name === 'request' && (
        <Request req={screen.req} onDone={(ok, title, detail) => setScreen({ name: 'done', ok, title, detail })}
          onExpired={() => setScreen({ name: 'done', ok: false, title: 'Request expired', detail: 'Start the sign-in again on your computer.' })} />
      )}
      {screen.name === 'done' && <Done {...screen} onBack={() => setScreen({ name: 'home' })} />}
    </SafeAreaView>
  )
}

function Home({ accounts, bio, status, onPair, onForget }: {
  accounts: Account[]; bio: { ok: boolean; kind: string | null; reason?: string } | null; status: string | null
  onPair: () => void; onForget: (a: Account) => void
}) {
  return (
    <ScrollView contentContainerStyle={s.body}>
      {bio && !bio.ok && (
        <View style={[s.card, { borderColor: C.amber }]}>
          <Text style={[s.cardTitle, { color: C.amber }]}>Fingerprint or face unlock not set up</Text>
          <Text style={s.mute}>Enrol a fingerprint (or Face ID) in your phone's settings. Approvals always require it. {bio.reason ?? ''}</Text>
        </View>
      )}
      {accounts.length === 0 ? (
        <View style={s.hero}>
          <Text style={s.heroTitle}>Sign in without a password.</Text>
          <Text style={[s.mute, { textAlign: 'center' }]}>Pair this phone with your Antiquarian's Cage account. When you sign in on a computer, approve here with your fingerprint or face.</Text>
        </View>
      ) : (
        <>
          <Text style={s.label}>PAIRED ACCOUNTS</Text>
          {accounts.map((a) => (
            <View key={a.authenticatorId} style={s.card}>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 12 }}>
                <View style={s.avatar}><Text style={s.avatarText}>{a.account.slice(0, 1).toUpperCase()}</Text></View>
                <View style={{ flex: 1 }}>
                  <Text style={s.cardTitle}>{a.account}</Text>
                  <Text style={s.mono}>{new URL(a.server).host}{checkServer(a.server).insecure ? ' · not encrypted (dev)' : ''}</Text>
                </View>
              </View>
              <Pressable onPress={() => Alert.alert('Remove from this phone?', 'Also remove the phone in the console (Account → Security) so it cannot be used.', [
                { text: 'Cancel', style: 'cancel' }, { text: 'Remove', style: 'destructive', onPress: () => onForget(a) }])}>
                <Text style={[s.link, { color: C.mute, marginTop: 10 }]}>Remove from this phone</Text>
              </Pressable>
            </View>
          ))}
          <View style={s.pill}><View style={s.dot} /><Text style={s.pillText}>LISTENING FOR SIGN-IN REQUESTS</Text></View>
          {status && <Text style={[s.mute, { color: C.amber, textAlign: 'center' }]}>{status}</Text>}
          <Text style={[s.mute, { textAlign: 'center', fontSize: 12 }]}>Keep this app open while you sign in on your computer.</Text>
        </>
      )}
      <Pressable style={s.primary} onPress={onPair}><Text style={s.primaryText}>{accounts.length ? 'Pair another account' : 'Pair with console'}</Text></Pressable>
      <Text style={[s.mute, { textAlign: 'center', fontSize: 12 }]}>Console → Account → Security → Phone authenticator → Pair a phone</Text>
    </ScrollView>
  )
}

function Scan({ onCancel, onPaired, onError }: { onCancel: () => void; onPaired: (a: Account) => void; onError: (m: string) => void }) {
  const [perm, request] = useCameraPermissions()
  const [busy, setBusy] = useState(false)
  const handled = useRef(false)

  if (!perm) return <ActivityIndicator color={C.green} style={{ marginTop: 40 }} />
  if (!perm.granted) {
    return (
      <View style={s.body}>
        <Text style={s.heroTitle}>Camera access</Text>
        <Text style={s.mute}>The camera is used only to scan the pairing code on your computer screen.</Text>
        <Pressable style={s.primary} onPress={request}><Text style={s.primaryText}>Allow camera</Text></Pressable>
        <Pressable onPress={onCancel}><Text style={s.link}>Cancel</Text></Pressable>
      </View>
    )
  }
  const onScan = async ({ data }: { data: string }) => {
    if (handled.current) return
    handled.current = true
    setBusy(true)
    try {
      const code = parsePairingCode(data)
      const name = `${Device.manufacturer ?? ''} ${Device.modelName ?? 'Phone'}`.trim().slice(0, 80)
      onPaired(await pair(code, name, Platform.OS === 'ios' ? 'ios' : 'android'))
    } catch (e) {
      onError((e as Error).message)
    }
  }
  return (
    <View style={{ flex: 1 }}>
      <CameraView style={{ flex: 1 }} facing="back" barcodeScannerSettings={{ barcodeTypes: ['qr'] }} onBarcodeScanned={busy ? undefined : onScan} />
      <View style={s.scanOverlay}>
        <Text style={s.cardTitle}>{busy ? 'Pairing… confirm with your fingerprint or face' : 'Scan the pairing code shown in the console'}</Text>
        {!busy && <Pressable onPress={onCancel}><Text style={s.link}>Cancel</Text></Pressable>}
      </View>
    </View>
  )
}

function describeClient(ua: string | null): string {
  if (!ua) return 'Unknown browser'
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser'
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : ''
  return `${browser}${os ? ` on ${os}` : ''}`
}

function Request({ req, onDone, onExpired }: { req: PendingRequest; onDone: (ok: boolean, t: string, d: string) => void; onExpired: () => void }) {
  const [busy, setBusy] = useState(false)
  const [left, setLeft] = useState(() => Math.round((new Date(req.expires_at).getTime() - Date.now()) / 1000))
  useEffect(() => {
    const t = setInterval(() => {
      const l = Math.round((new Date(req.expires_at).getTime() - Date.now()) / 1000)
      setLeft(l)
      if (l <= 0 && !busy) onExpired()
    }, 500)
    return () => clearInterval(t)
  }, [req.expires_at, busy, onExpired])

  const act = async (decision: 'approve' | 'deny', number: number) => {
    setBusy(true)
    try {
      const r = await decide(req, decision, number)
      if (r === 'approved') onDone(true, 'Verified', 'Identity confirmed. Your computer is signing you in.')
      else onDone(false, 'Sign-in blocked', decision === 'deny'
        ? 'You denied the request. Your security team has been alerted.'
        : 'That number did not match your screen, so the sign-in was blocked and your security team alerted.')
    } catch (e) {
      setBusy(false)
      Alert.alert('Not confirmed', (e as Error).message)
    }
  }
  const what = req.purpose === 'windows' ? `Windows sign-in on ${req.context.device ?? 'a computer'}`
    : req.purpose === 'windows_enroll' ? `Set up phone sign-in for Windows on ${req.context.device ?? 'a computer'}`
      : 'Console sign-in'
  return (
    <ScrollView contentContainerStyle={s.body}>
      <View style={s.card}>
        <Text style={s.label}>SIGN-IN REQUEST</Text>
        <Text style={s.reqTitle}>{what}</Text>
        <Text style={s.mute}>{req.account.account}{req.organization ? ` · ${req.organization}` : ''}</Text>
        {req.context.windows_user && <Text style={s.mute}>Windows account {req.context.windows_user}</Text>}
        <Text style={[s.mono, { marginTop: 8 }]}>{req.purpose === 'console' ? describeClient(req.client) : 'Lock screen'} · {req.ip ?? 'unknown address'} · {Math.max(0, left)}s left</Text>
      </View>
      <Text style={[s.cardTitle, { textAlign: 'center', marginTop: 8 }]}>Tap the number shown on your screen</Text>
      <View style={s.numbers}>
        {req.choices.map((n) => (
          <Pressable key={n} disabled={busy} onPress={() => act('approve', n)} style={({ pressed }) => [s.numberBtn, pressed && { borderColor: C.green }]}>
            <Text style={s.number}>{n}</Text>
          </Pressable>
        ))}
      </View>
      {busy && <ActivityIndicator color={C.green} />}
      <Text style={[s.mute, { textAlign: 'center', fontSize: 12 }]}>You'll be asked for your fingerprint or face. If you didn't try to sign in, deny.</Text>
      <Pressable disabled={busy} style={s.deny} onPress={() => act('deny', 0)}><Text style={s.denyText}>Deny — this wasn't me</Text></Pressable>
    </ScrollView>
  )
}

function Done({ ok, title, detail, onBack }: { ok: boolean; title: string; detail: string; onBack: () => void }) {
  useEffect(() => { if (ok) { const t = setTimeout(onBack, 2500); return () => clearTimeout(t) } }, [ok, onBack])
  return (
    <View style={[s.body, { alignItems: 'center', justifyContent: 'center', flex: 1 }]}>
      <View style={[s.ring, { borderColor: ok ? C.green : C.red }]}><Text style={{ fontSize: 44, color: ok ? C.green : C.red }}>{ok ? '✓' : '!'}</Text></View>
      <Text style={s.heroTitle}>{title}</Text>
      <Text style={[s.mute, { textAlign: 'center' }]}>{detail}</Text>
      <Pressable style={s.primary} onPress={onBack}><Text style={s.primaryText}>Done</Text></Pressable>
    </View>
  )
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20, paddingTop: 44, paddingBottom: 12, borderBottomWidth: 1, borderColor: C.line },
  brand: { color: C.text, fontWeight: '700', letterSpacing: 2, fontSize: 13 },
  shield: { color: C.green, fontSize: 18 },
  body: { padding: 20, gap: 14 },
  hero: { alignItems: 'center', gap: 10, paddingVertical: 40 },
  heroTitle: { color: C.text, fontSize: 24, fontWeight: '700', textAlign: 'center' },
  card: { backgroundColor: C.card, borderColor: C.line, borderWidth: 1, borderRadius: 16, padding: 16, gap: 4 },
  cardTitle: { color: C.text, fontSize: 16, fontWeight: '600' },
  reqTitle: { color: C.text, fontSize: 22, fontWeight: '700', marginTop: 4 },
  label: { color: C.green, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', letterSpacing: 2, fontSize: 11 },
  mono: { color: C.mute, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 12 },
  mute: { color: C.mute, fontSize: 14, lineHeight: 20 },
  avatar: { width: 40, height: 40, borderRadius: 20, backgroundColor: C.greenDim, alignItems: 'center', justifyContent: 'center' },
  avatarText: { color: C.text, fontWeight: '700' },
  primary: { backgroundColor: C.green, borderRadius: 999, paddingVertical: 15, alignItems: 'center', marginTop: 6 },
  primaryText: { color: '#03140a', fontWeight: '700', fontSize: 16 },
  link: { color: C.green, textAlign: 'center', fontWeight: '600' },
  pill: { flexDirection: 'row', alignSelf: 'center', alignItems: 'center', gap: 8, borderWidth: 1, borderColor: C.line, borderRadius: 999, paddingHorizontal: 14, paddingVertical: 7 },
  dot: { width: 7, height: 7, borderRadius: 4, backgroundColor: C.green },
  pillText: { color: C.text, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 11, letterSpacing: 1.5 },
  numbers: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  numberBtn: { flex: 1, aspectRatio: 1, borderRadius: 20, borderWidth: 2, borderColor: C.line, backgroundColor: C.card, alignItems: 'center', justifyContent: 'center' },
  number: { color: C.text, fontSize: 40, fontWeight: '700' },
  deny: { borderRadius: 999, paddingVertical: 14, alignItems: 'center', borderWidth: 1, borderColor: '#3a1c1c', backgroundColor: '#140909' },
  denyText: { color: C.red, fontWeight: '600' },
  ring: { width: 110, height: 110, borderRadius: 55, borderWidth: 3, alignItems: 'center', justifyContent: 'center', marginBottom: 10 },
  scanOverlay: { position: 'absolute', bottom: 0, left: 0, right: 0, padding: 24, gap: 12, backgroundColor: 'rgba(5,8,6,0.88)' },
})
