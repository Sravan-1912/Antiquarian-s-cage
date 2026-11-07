import { expect, test, type Page } from '@playwright/test'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const STATE = path.resolve(__dirname, '..', '.e2e-state')
const OUTBOX = path.join(STATE, 'outbox')
const PASSWORD = 'Correct-Horse-Battery-9'
const ADMIN = 'owner@example.com'
const ANALYST = 'analyst@example.com'

/** Newest token link of the given path from the dev mail outbox (quoted-printable aware). */
function lastLink(linkPath: string, to: string): string {
  const files = fs.existsSync(OUTBOX) ? fs.readdirSync(OUTBOX).filter((f) => f.endsWith('.eml')) : []
  const sorted = files.map((f) => path.join(OUTBOX, f)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)
  for (const f of sorted) {
    const raw = fs.readFileSync(f, 'utf8').replace(/=\r?\n/g, '').replace(/=3D/g, '=')
    if (!raw.toLowerCase().includes(to.toLowerCase())) continue
    const m = raw.match(new RegExp(`${linkPath.replace('/', '\\/')}\\?token=([A-Za-z0-9_\\-]+)`))
    if (m) return `${linkPath}?token=${m[1]}`
  }
  throw new Error(`no ${linkPath} email for ${to}`)
}

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits) so the suite can enrol and use MFA like a real authenticator app. */
function totp(base32: string, at = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of base32.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)))
  const h = crypto.createHmac('sha1', key).update(counter).digest()
  const o = h[h.length - 1] & 0xf
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

async function signIn(page: Page, email: string, password = PASSWORD) {
  await page.goto('/login')
  await page.getByLabel('Work email').fill(email)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in with password' }).click()
}

let mfaSecret = ''

test('first run: set up organisation, verify email, sign in, reach the dashboard', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByLabel('Organisation name').fill('E2E Corp')
  await page.getByLabel('Full name').fill('Olive Owner')
  await page.getByLabel('Work email').fill(ADMIN)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByLabel('Confirm password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Create organisation' }).click()
  await expect(page.getByRole('heading', { name: 'Check your email' })).toBeVisible()

  // Signing in before verification is refused.
  await signIn(page, ADMIN)
  await expect(page.getByText(/verif/i).first()).toBeVisible()

  await page.goto(lastLink('/verify-email', ADMIN))
  await expect(page.getByText(/verified/i).first()).toBeVisible()
  await signIn(page, ADMIN)
  await expect(page.getByRole('heading', { name: /overview|dashboard/i }).first()).toBeVisible()
})

test('wrong password is rejected without revealing whether the account exists', async ({ page }) => {
  await signIn(page, ADMIN, 'Wrong-Password-123')
  const known = await page.getByRole('alert').first().textContent()
  await signIn(page, 'nobody@example.com', 'Wrong-Password-123')
  const unknown = await page.getByRole('alert').first().textContent()
  expect(known?.trim()).toBe(unknown?.trim())
})

test('enrol TOTP MFA, then sign-in requires the code', async ({ page }) => {
  await signIn(page, ADMIN)
  await expect(page.getByRole('heading', { name: /overview|dashboard/i }).first()).toBeVisible()
  await page.goto('/account/security')
  await page.getByRole('button', { name: 'Set up authenticator app' }).click()
  const key = page.locator('code').filter({ hasText: /^[A-Z2-7 ]{16,}$/ }).first()
  mfaSecret = (await key.textContent())!.replace(/\s/g, '')
  await page.getByLabel('Enter the 6-digit code to confirm').fill(totp(mfaSecret))
  await page.getByRole('button', { name: 'Enable MFA' }).click()
  await expect(page.getByText('MFA enabled.', { exact: false })).toBeVisible()

  await page.context().clearCookies()
  await signIn(page, ADMIN)
  await expect(page).toHaveURL(/\/mfa/)
  await page.getByLabel('Authentication code').fill('000000')
  await page.getByRole('button', { name: /verify|continue|sign in/i }).click()
  await expect(page.getByRole('alert').first()).toBeVisible()
  // A fresh time step avoids the server's replay protection for the code used during enrolment.
  await page.waitForTimeout(31_000 - (Date.now() % 30_000))
  await page.getByLabel('Authentication code').fill(totp(mfaSecret))
  await page.getByRole('button', { name: /verify|continue|sign in/i }).click()
  await expect(page.getByRole('heading', { name: /overview|dashboard/i }).first()).toBeVisible()
})

async function adminSession(page: Page) {
  await signIn(page, ADMIN)
  await page.waitForURL((u) => !u.pathname.startsWith('/login'))
  if (/\/mfa/.test(page.url())) {
    await page.getByLabel('Authentication code').fill(totp(mfaSecret))
    await page.getByRole('button', { name: /verify|continue|sign in/i }).click()
  }
  await expect(page.getByRole('heading', { name: /overview|dashboard/i }).first()).toBeVisible()
}

test('create an employee and see it in the directory and the audit log', async ({ page }) => {
  test.skip(!mfaSecret, 'depends on the MFA test')
  await page.waitForTimeout(31_000 - (Date.now() % 30_000)) // new TOTP step (replay protection)
  await adminSession(page)
  await page.goto('/employees')
  await page.getByRole('button', { name: /Add (the first )?employee/ }).first().click()
  await page.getByRole('dialog').getByLabel('Employee ID').fill('E-100')
  await page.getByRole('dialog').getByLabel('Full name').fill('Grace Hopper')
  await page.getByRole('dialog').getByLabel('Work email').fill('grace@example.com')
  await page.getByRole('dialog').getByLabel('Department').fill('Engineering')
  await page.getByRole('dialog').getByLabel('Job title').fill('Engineer')
  await page.getByRole('dialog').getByRole('button', { name: 'Create employee' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.goto('/employees')
  await expect(page.getByText('Grace Hopper')).toBeVisible()

  await page.goto('/audit')
  await expect(page.getByRole('cell', { name: 'employee.created' }).first()).toBeVisible()
  await page.getByRole('button', { name: 'Verify integrity' }).click()
  await expect(page.getByText('Chain intact')).toBeVisible()
})

test('invited Security Analyst cannot create employees or manage administrators', async ({ page, browser }) => {
  test.skip(!mfaSecret, 'depends on the MFA test')
  await page.waitForTimeout(31_000 - (Date.now() % 30_000))
  await adminSession(page)
  await page.goto('/administrators')
  await page.getByRole('button', { name: 'Invite administrator' }).click()
  await page.getByRole('dialog').getByLabel('Full name').fill('Ana Lyst')
  await page.getByRole('dialog').getByLabel('Work email').fill(ANALYST)
  await page.getByRole('dialog').getByLabel('Role').selectOption({ label: 'Security Analyst' })
  await page.getByRole('button', { name: 'Send invitation' }).click()
  await expect(page.getByText(`Invitation sent to ${ANALYST}`)).toBeVisible()

  const ctx = await browser.newContext()
  const p2 = await ctx.newPage()
  await p2.goto(lastLink('/accept-invite', ANALYST))
  await p2.getByLabel('New password').fill(PASSWORD)
  await p2.getByLabel('Confirm password').fill(PASSWORD)
  await p2.getByRole('button', { name: 'Set password' }).click()
  await expect(p2.getByRole('alert').first()).toBeVisible()
  await signIn(p2, ANALYST)
  await expect(p2.getByRole('heading', { name: /overview|dashboard/i }).first()).toBeVisible()

  // UI hides what the role cannot do...
  await p2.goto('/employees')
  await expect(p2.getByRole('button', { name: /Add (the first )?employee/ })).toHaveCount(0)
  // ...and the backend refuses it even when called directly.
  const csrf = (await ctx.cookies()).find((c) => c.name === 'cage_csrf')?.value ?? ''
  const r = await p2.request.post('/api/v1/employees', {
    headers: { 'X-CSRF-Token': csrf },
    data: { employee_number: 'E-999', full_name: 'Nope', email: 'nope@example.com', department: 'X', job_title: 'Y' },
  })
  expect(r.status()).toBe(403)
  const users = await p2.request.post('/api/v1/users', {
    headers: { 'X-CSRF-Token': csrf }, data: { email: 'x@example.com', full_name: 'X Y', role: 'super_admin' },
  })
  expect(users.status()).toBe(403)
  await ctx.close()
})
