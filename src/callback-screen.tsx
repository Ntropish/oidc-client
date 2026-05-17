import type { ReactNode } from 'react';
import { useAuth } from './react';

const SPINNER_KEYFRAMES_ID = 'trivorn-auth-spinner-keyframes';
const SPINNER_KEYFRAMES = '@keyframes trivorn-auth-spinner { to { transform: rotate(360deg); } }';

function ensureKeyframes() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(SPINNER_KEYFRAMES_ID)) return;
  const style = document.createElement('style');
  style.id = SPINNER_KEYFRAMES_ID;
  style.textContent = SPINNER_KEYFRAMES;
  document.head.appendChild(style);
}

function Spinner({ size = 40 }: { size?: number }) {
  ensureKeyframes();
  const stroke = Math.max(2, Math.round(size / 16));
  const r = (size - stroke) / 2;
  const c = size / 2;
  const circumference = 2 * Math.PI * r;
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      style={{ animation: 'trivorn-auth-spinner 0.9s linear infinite' }}
      aria-hidden="true"
    >
      <circle
        cx={c}
        cy={c}
        r={r}
        fill="none"
        stroke="var(--border, rgba(0,0,0,0.12))"
        strokeWidth={stroke}
      />
      <circle
        cx={c}
        cy={c}
        r={r}
        fill="none"
        stroke="var(--primary, #4f46e5)"
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${circumference * 0.25} ${circumference}`}
      />
    </svg>
  );
}

interface AuthLoadingScreenProps {
  /** Override the default "Signing you in…" label. */
  label?: string;
  /** When set, default label becomes "Signing you into {appName}…". Ignored if `label` is set. */
  appName?: string;
  /** Render an error state instead of the spinner. */
  error?: Error | null;
  /** Optional retry handler shown alongside the error message. */
  onRetry?: () => void;
}

export function AuthLoadingScreen({ label, appName, error, onRetry }: AuthLoadingScreenProps) {
  const containerStyle: React.CSSProperties = {
    position: 'fixed',
    inset: 0,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 16,
    padding: 24,
    backgroundColor: 'var(--surface, #ffffff)',
    color: 'var(--on-surface, #1a1a1a)',
    fontFamily: 'inherit',
    fontSize: 14,
    textAlign: 'center',
  };

  if (error) {
    return (
      <div style={containerStyle} role="alert">
        <h2 style={{ margin: 0, fontSize: 18, color: 'var(--on-surface, #1a1a1a)' }}>
          Sign-in failed
        </h2>
        <p style={{ margin: 0, color: 'var(--on-surface-muted, #6b7280)', maxWidth: 480 }}>
          {error.message || 'Authentication did not complete.'}
        </p>
        {onRetry ? (
          <button
            type="button"
            onClick={onRetry}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              border: '1px solid var(--border, rgba(0,0,0,0.12))',
              backgroundColor: 'var(--primary, #4f46e5)',
              color: 'var(--on-primary, #ffffff)',
              fontSize: 14,
              fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        ) : null}
      </div>
    );
  }

  const text = label ?? (appName ? `Signing you into ${appName}…` : 'Signing you in…');

  return (
    <div style={containerStyle}>
      <Spinner />
      <span style={{ color: 'var(--on-surface-muted, #6b7280)' }}>{text}</span>
    </div>
  );
}

interface AuthGateProps {
  children: ReactNode;
  /** Override the default loading screen. */
  fallback?: ReactNode;
  /** Override the default error screen. */
  errorFallback?: (error: Error, retry: () => void) => ReactNode;
  /** Forwarded to the default loading screen. */
  appName?: string;
}

/**
 * Drop-in wrapper for apps that want the consent → callback → app
 * transition to render a themed splash. Renders the loading screen while
 * `useAuth()` is initializing, an error screen if the callback exchange
 * failed, and `children` once auth is settled. Place inside `<AuthProvider>`.
 */
export function AuthGate({ children, fallback, errorFallback, appName }: AuthGateProps) {
  const { isLoading, error } = useAuth();

  if (error) {
    const retry = () => {
      window.location.reload();
    };
    if (errorFallback) return <>{errorFallback(error, retry)}</>;
    return <AuthLoadingScreen error={error} onRetry={retry} appName={appName} />;
  }

  if (isLoading) {
    return <>{fallback ?? <AuthLoadingScreen appName={appName} />}</>;
  }

  return <>{children}</>;
}
