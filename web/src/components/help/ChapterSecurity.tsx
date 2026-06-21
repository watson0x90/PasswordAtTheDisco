// ChapterSecurity — Chapter 4 of the Help / Methodology surface: "Security &
// privacy". The CISO data-handling reassurance chapter. Every claim here is true
// of the shipped tool and matches the security model in CLAUDE.md — no
// overclaiming. Presented as scannable assurance cards grouped by theme.
//
//   - Data handling: no cleartext on disk; encrypted-at-rest store + DEK
//     re-keying; cleartext only ever in process memory.
//   - Access control: redacted-by-default APIs; lead-only, one-at-a-time,
//     audit-logged reveal (the audit log never contains the password); RBAC.
//   - Transport & session: HttpOnly / SameSite=Strict cookies; strict CSP +
//     security headers; TLS fail-closed in production.
//   - Build & supply chain: single static CGO-free binary; vetted, exact-pinned
//     dependencies; stdlib-first.
//
// PURE STATIC: no auth, no api, no data providers, no dynamic values. Static copy
// only. A later review asserts this.

import { type ReactNode } from "react"

type Assurance = { k: string; body: ReactNode }
type Group = { tag: string; title: string; accent: "data" | "access" | "transport" | "build"; items: Assurance[] }

const GROUPS: Group[] = [
  {
    tag: "Data handling",
    title: "Cracked passwords never touch the disk",
    accent: "data",
    items: [
      {
        k: "No cleartext on disk",
        body: (
          <>
            A recovered password lives <strong>only in process memory</strong>. The tool writes no report, cache, or log
            that contains a working credential — the exposure ends when the process does.
          </>
        ),
      },
      {
        k: "Encrypted at rest",
        body: (
          <>
            The persistent store is <strong>encrypted at rest</strong> under a data-encryption key, and that key can be{" "}
            <strong>re-keyed</strong> in place — so the on-disk state can be rotated to a fresh key without re-importing the
            audit.
          </>
        ),
      },
      {
        k: "Memory-only by design",
        body: (
          <>
            Cleartext exists only while it is needed, in RAM, behind the access controls below. There is no file to find
            later and no artifact that outlives the engagement.
          </>
        ),
      },
    ],
  },
  {
    tag: "Access control",
    title: "Redacted by default, revealed deliberately",
    accent: "access",
    items: [
      {
        k: "Redacted-by-default APIs",
        body: (
          <>
            Every endpoint returns redacted data by default. A cleartext password is never part of an ordinary account
            response — it is the <strong>exception</strong>, not the norm.
          </>
        ),
      },
      {
        k: "Lead-only, one account at a time",
        body: (
          <>
            Revealing a cleartext password is a <strong>lead-role-only</strong> action, performed for a{" "}
            <strong>single account at a time</strong> — never a bulk export.
          </>
        ),
      },
      {
        k: "Logged, never the password",
        body: (
          <>
            Every reveal is <strong>audit-logged</strong> — who, which account, when — so access is accountable. The audit
            log <strong>never contains the password itself</strong>.
          </>
        ),
      },
      {
        k: "Role-based access (RBAC)",
        body: (
          <>
            Operators are scoped by role; sensitive actions are gated behind the <code>lead</code> role. Capability follows
            the role, not the session.
          </>
        ),
      },
    ],
  },
  {
    tag: "Transport & session",
    title: "Hardened in transit and in the browser",
    accent: "transport",
    items: [
      {
        k: "HttpOnly · SameSite=Strict cookies",
        body: (
          <>
            Sessions are carried in <strong>HttpOnly</strong>, <strong>SameSite=Strict</strong> cookies — unreadable by
            page scripts and not sent on cross-site requests.
          </>
        ),
      },
      {
        k: "Strict CSP + security headers",
        body: (
          <>
            A <strong>strict Content-Security-Policy</strong> and a full set of security response headers ship with every
            response, shrinking the client-side attack surface.
          </>
        ),
      },
      {
        k: "TLS fail-closed in production",
        body: (
          <>
            In production the server <strong>fails closed</strong> without TLS — it will not serve audit data over an
            unencrypted channel rather than silently downgrading.
          </>
        ),
      },
    ],
  },
  {
    tag: "Build & supply chain",
    title: "One vetted binary, nothing implicit",
    accent: "build",
    items: [
      {
        k: "Single static CGO-free binary",
        body: (
          <>
            The whole tool — API, scoring engine, and the React UI — ships as one <strong>static, CGO-free binary</strong>.
            Nothing is installed on the host and the frontend is embedded, not served from a separate stack.
          </>
        ),
      },
      {
        k: "Vetted, exact-pinned dependencies",
        body: (
          <>
            Every dependency is <strong>CVE-vetted before use</strong> and <strong>exact-pinned</strong> with integrity
            hashes in the committed lockfiles — no floating ranges, no surprise upgrades.
          </>
        ),
      },
      {
        k: "Stdlib-first",
        body: (
          <>
            The backend is <strong>standard-library-first</strong>, with the dependency tree kept deliberately tiny —
            fewer moving parts to trust, audit, and keep clean.
          </>
        ),
      },
    ],
  },
]

export function ChapterSecurity() {
  return (
    <div className="help-chapter help-security">
      <section className="help-hero help-hero-compact">
        <span className="help-hero-eyebrow">Security &amp; privacy</span>
        <h1 className="help-hero-title">
          Built to be safe<span className="help-hero-mark"> to hand a CISO.</span>
        </h1>
        <p className="help-hero-lede">
          This tool handles the most sensitive output of an audit — working credentials and the AD blast radius behind
          them. Every control below is part of the shipped design, chosen so the answer to &ldquo;where could this leak?&rdquo;
          is <strong>nowhere it isn&rsquo;t supposed to.</strong>
        </p>
      </section>

      <div className="sec-groups">
        {GROUPS.map((g) => (
          <section key={g.tag} className={`sec-group ${g.accent}`} aria-label={g.title}>
            <header className="sec-group-head">
              <span className="sec-group-tag">{g.tag}</span>
              <h2 className="sec-group-title">{g.title}</h2>
            </header>
            <ul className="sec-cards">
              {g.items.map((it) => (
                <li key={it.k} className="sec-card">
                  <span className="sec-card-k">{it.k}</span>
                  <p className="sec-card-body">{it.body}</p>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>

      <p className="sec-foot">
        None of these are aspirational. They describe how the binary you are running behaves today — see the project&rsquo;s
        architecture and security model for the implementation detail behind each line.
      </p>
    </div>
  )
}
