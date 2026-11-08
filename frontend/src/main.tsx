import { StrictMode, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import './index.css'
import { AuthProvider, useAuth } from '@/hooks/useAuth'
import { AppShell } from '@/layouts/AppShell'
import { Spinner } from '@/components/ui/primitives'
import {
  AcceptInvitePage, ForgotPasswordPage, LoginPage, MfaChallengePage, RecoverPage, ResetPasswordPage, SetupPage, SsoErrorPage, VerifyEmailPage,
} from '@/pages/auth/AuthPages'
import { DashboardPage } from '@/modules/dashboard/DashboardPage'
import { EmployeesPage } from '@/modules/employees/EmployeesPage'
import { EmployeeDetailPage } from '@/modules/employees/EmployeeDetailPage'
import { AdministratorsPage } from '@/modules/identity/AdministratorsPage'
import { AccountSecurityPage } from '@/modules/identity/AccountSecurityPage'
import { AuditPage } from '@/modules/audit/AuditPage'
import { EndpointsPage } from '@/modules/devices/EndpointsPage'
import { EndpointDetailPage } from '@/modules/devices/EndpointDetailPage'
import { NotificationsPage } from '@/pages/NotificationsPage'
import { PoliciesPage } from '@/modules/policies/PoliciesPage'
import { PolicyDetailPage } from '@/modules/policies/PolicyDetailPage'
import { CompliancePage } from '@/modules/compliance/CompliancePage'
import { RemoteSessionsPage } from '@/modules/remote/RemoteSessionsPage'
import { ApplicationDetailPage, ApplicationsPage } from '@/modules/applications/ApplicationsPage'
import { WorkspacePage } from '@/modules/workspace/WorkspacePage'
import { AlertDetailPage, AlertsPage } from '@/modules/alerts/AlertsPage'
import { ReportsPage } from '@/modules/reports/ReportsPage'
import { ApiError } from '@/services/api'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
    },
  },
})

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth()
  const loc = useLocation()
  if (loading) return <div className="grid h-full place-items-center"><Spinner /></div>
  if (!me) return <Navigate to="/login" replace state={{ from: loc.pathname }} />
  return <>{children}</>
}

function Gate({ perm, children }: { perm: string; children: ReactNode }) {
  const { can } = useAuth()
  if (!can(perm)) {
    return (
      <div className="py-16 text-center">
        <p className="text-sm text-silver-200">You do not have access to this area.</p>
        <p className="mt-1 text-xs text-silver-500">Required permission: <code>{perm}</code></p>
      </div>
    )
  }
  return <>{children}</>
}

function GateAny({ perms, children }: { perms: string[]; children: ReactNode }) {
  const { can } = useAuth()
  return perms.some(can) ? <>{children}</> : <Gate perm={perms[0]}>{children}</Gate>
}

function Home() {
  const { can } = useAuth()
  if (can('dashboard:read')) return <DashboardPage />
  return <Navigate to={can('self:read') ? '/workspace' : '/account/security'} replace />
}

function NotFound() {
  return <div className="py-16 text-center text-sm text-silver-400">Page not found. <Link className="text-emerald-400" to="/">Return to dashboard</Link></div>
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/mfa" element={<MfaChallengePage />} />
            <Route path="/setup" element={<SetupPage />} />
            <Route path="/verify-email" element={<VerifyEmailPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/accept-invite" element={<AcceptInvitePage />} />
            <Route path="/recover" element={<RecoverPage />} />
            <Route path="/sso-error" element={<SsoErrorPage />} />
            <Route element={<RequireAuth><AppShell /></RequireAuth>}>
              <Route index element={<Home />} />
              <Route path="employees" element={<Gate perm="employees:read"><EmployeesPage /></Gate>} />
              <Route path="employees/:id" element={<Gate perm="employees:read"><EmployeeDetailPage /></Gate>} />
              <Route path="endpoints" element={<GateAny perms={['devices:read', 'devices:read_assigned']}><EndpointsPage /></GateAny>} />
              <Route path="endpoints/:id" element={<GateAny perms={['devices:read', 'devices:read_assigned']}><EndpointDetailPage /></GateAny>} />
              <Route path="alerts" element={<Gate perm="alerts:read"><AlertsPage /></Gate>} />
              <Route path="alerts/:id" element={<Gate perm="alerts:read"><AlertDetailPage /></Gate>} />
              <Route path="reports" element={<Gate perm="reports:read"><ReportsPage /></Gate>} />
              <Route path="applications" element={<Gate perm="applications:read"><ApplicationsPage /></Gate>} />
              <Route path="applications/:id" element={<Gate perm="applications:read"><ApplicationDetailPage /></Gate>} />
              <Route path="workspace" element={<Gate perm="self:read"><WorkspacePage /></Gate>} />
              <Route path="remote-sessions" element={<GateAny perms={['devices:read', 'devices:read_assigned']}><RemoteSessionsPage /></GateAny>} />
              <Route path="policies" element={<Gate perm="policies:read"><PoliciesPage /></Gate>} />
              <Route path="policies/:id" element={<Gate perm="policies:read"><PolicyDetailPage /></Gate>} />
              <Route path="compliance" element={<Gate perm="compliance:read"><CompliancePage /></Gate>} />
              <Route path="administrators" element={<Gate perm="users:read"><AdministratorsPage /></Gate>} />
              <Route path="audit" element={<Gate perm="audit:read"><AuditPage /></Gate>} />
              <Route path="notifications" element={<NotificationsPage />} />
              <Route path="account/security" element={<AccountSecurityPage />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
