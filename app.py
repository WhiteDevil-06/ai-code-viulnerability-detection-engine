"""
app.py — VulnScanner AI
SaaS Dashboard: Landing → Login/Register → Dashboard
Auth: Supabase email/password only
UI: Pure HTML sections for pixel-accurate mockup matching
"""
import os
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client
from styles import GLOBAL_CSS, PARTICLES_HTML

# ── Env ────────────────────────────────────────────────────────────────────────
load_dotenv()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VulnScanner AI",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
st.markdown(PARTICLES_HTML, unsafe_allow_html=True)

# ── Supabase ───────────────────────────────────────────────────────────────────
@st.cache_resource
def _sb() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)
supabase = _sb()

# ── Preload scanner (avoids freeze on first scan) ─────────────────────────────
@st.cache_resource(show_spinner=False)
def _load():
    try:
        from github_scanner import GitHubScanner
        return GitHubScanner()
    except Exception:
        return None
scanner = _load()
engine_ready = scanner is not None

# ── Session state ──────────────────────────────────────────────────────────────
_defaults = {"page": "landing", "user": None, "last_result": None}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Helpers ────────────────────────────────────────────────────────────────────
def _go(p):
    st.session_state.page = p
    st.rerun()

def _logout():
    try: supabase.auth.sign_out()
    except: pass
    st.session_state.user = None
    st.session_state.last_result = None
    _go("landing")

def _save(target, files, vulns, report):
    try:
        uid = st.session_state.user.user.id
        supabase.table("scans").insert({
            "user_id": uid, "target": target,
            "files_scanned": files,
            "vulnerabilities_found": vulns,
            "report_json": report
        }).execute()
    except Exception:
        pass

FOOTER = """
<div class="footer">
    Developed by <b>Rakshith Raghavendra</b>
    <span style="color:#1e293b;margin:0 .75rem">·</span>
    VulnScanner AI © 2025
</div>
"""

# ══════════════════════════════════════════════════════════════════════════════
# LANDING PAGE
# ══════════════════════════════════════════════════════════════════════════════
def page_landing():
    # ── Navbar ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="navbar">
        <div class="nav-logo">🔐 <span>VulnScanner AI</span></div>
        <div class="nav-right" id="nav-right-slot"></div>
    </div>""", unsafe_allow_html=True)

    # Navbar login button — placed with CSS float trick
    st.markdown("<div style='position:fixed;top:.85rem;right:2.5rem;z-index:1001;'>", unsafe_allow_html=True)
    if st.button("Login →", key="nav_login"):
        _go("login")
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Hero ──────────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero-wrap">
        <div class="hero-badge">🤖&nbsp;&nbsp;AI-Powered Security Scanner</div>
        <h1 class="hero-title">Find Vulnerabilities<br>Before Hackers Do</h1>
        <p class="hero-sub">Our machine learning engine scans Python code and GitHub repositories
        for SQL Injection, Command Injection, XSS, and Unsafe Eval — in seconds.</p>
    </div>""", unsafe_allow_html=True)

    # CTA button — CSS centers it automatically via div.stButton rule
    if st.button("🚀  Get Started Free", key="cta"):
        _go("login")

    # ── Features ──────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="section-wrap">
        <h2 class="section-title">Why VulnScanner AI?</h2>
        <p class="section-sub">Built for developers who ship fast without sacrificing security.</p>
        <div class="grid-3">
            <div class="feat-card">
                <div class="feat-icon">🤖</div>
                <div class="feat-title">AI-Powered Detection</div>
                <div class="feat-desc">Machine learning trained on real vulnerability patterns across thousands of code samples.</div>
            </div>
            <div class="feat-card">
                <div class="feat-icon">⚡</div>
                <div class="feat-title">Lightning Fast</div>
                <div class="feat-desc">Full repository scans complete in seconds, not hours. Zero setup required.</div>
            </div>
            <div class="feat-card">
                <div class="feat-icon">🔒</div>
                <div class="feat-title">Secure by Design</div>
                <div class="feat-desc">Row-level security ensures only you can see your reports. Your code stays private.</div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

    # ── How It Works ──────────────────────────────────────────────────────────
    st.markdown("""
    <div class="section-wrap" style="padding-top:0">
        <h2 class="section-title">How It Works</h2>
        <p class="section-sub">Three steps to a secure codebase.</p>
        <div class="grid-3">
            <div class="step-card">
                <div class="step-num">1</div>
                <div class="step-title">Connect</div>
                <div class="step-desc">Paste your Python code or enter any public GitHub repository URL.</div>
            </div>
            <div class="step-card">
                <div class="step-num">2</div>
                <div class="step-title">Scan</div>
                <div class="step-desc">Our AI engine analyses every function and file for known vulnerability patterns.</div>
            </div>
            <div class="step-card">
                <div class="step-num">3</div>
                <div class="step-title">Report</div>
                <div class="step-desc">Get a detailed breakdown with risk levels and the exact files affected.</div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

    # ── Metrics ───────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="section-wrap" style="padding-top:0">
        <div class="grid-4">
            <div class="metric-card"><div class="metric-val">750+</div><div class="metric-lbl">Training Samples</div></div>
            <div class="metric-card"><div class="metric-val">4</div><div class="metric-lbl">Vulnerability Types</div></div>
            <div class="metric-card"><div class="metric-val">&lt;30s</div><div class="metric-lbl">Scan Speed</div></div>
            <div class="metric-card"><div class="metric-val">100%</div><div class="metric-lbl">Model v1 Accuracy</div></div>
        </div>
    </div>""", unsafe_allow_html=True)

    st.markdown(FOOTER, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN / REGISTER PAGE
# ══════════════════════════════════════════════════════════════════════════════
def page_login():
    st.markdown("""
    <div class="navbar">
        <div class="nav-logo">🔐 <span>VulnScanner AI</span></div>
    </div>""", unsafe_allow_html=True)

    # Centered form card using a wrapper div
    st.markdown("<div class='auth-center'>", unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-card" style="width:100%;max-width:460px;margin:3rem auto 0;">
        <div style="text-align:center;margin-bottom:2rem;">
            <div style="font-size:2rem;font-weight:900;color:#e2e8f0;">Welcome Back</div>
            <p style="color:#64748b;margin-top:.4rem;font-size:.95rem;">
                Sign in to access your security dashboard
            </p>
        </div>
    """, unsafe_allow_html=True)

    tab_login, tab_reg = st.tabs(["Login", "Register"])

    with tab_login:
        email = st.text_input("Email address", placeholder="you@example.com", key="li_email",
                               label_visibility="collapsed")
        pw    = st.text_input("Password", type="password", placeholder="Password", key="li_pw",
                               label_visibility="collapsed")
        if st.button("Login", key="do_login"):
            if not email or not pw:
                st.error("Please enter your email and password.")
            else:
                try:
                    resp = supabase.auth.sign_in_with_password({"email": email, "password": pw})
                    st.session_state.user = resp
                    _go("dashboard")
                except Exception as e:
                    err = str(e)
                    if "Invalid login credentials" in err:
                        st.error("❌ Incorrect email or password.")
                    elif "Email not confirmed" in err:
                        st.error("✉️ Please verify your email first.")
                    else:
                        st.error(f"Login failed: {err}")

    with tab_reg:
        re  = st.text_input("Email address", placeholder="you@example.com", key="re_email",
                             label_visibility="collapsed")
        rpw = st.text_input("Password", type="password", placeholder="Choose a password (min 6 chars)",
                             key="re_pw", label_visibility="collapsed")
        if st.button("Create Account", key="do_reg"):
            if not re or not rpw:
                st.error("Please fill in both fields.")
            elif len(rpw) < 6:
                st.error("Password must be at least 6 characters.")
            else:
                try:
                    supabase.auth.sign_up({"email": re, "password": rpw})
                    st.success("✅ Account created! Switch to the Login tab to sign in.")
                except Exception as e:
                    err = str(e)
                    if "already registered" in err or "already exists" in err:
                        st.warning("This email is already registered — please login instead.")
                    else:
                        st.error(f"Registration failed: {err}")

    st.markdown("</div>", unsafe_allow_html=True)  # close glass-card
    st.markdown("</div>", unsafe_allow_html=True)  # close auth-center

    st.markdown("<div style='text-align:center;margin-top:1.5rem;'>", unsafe_allow_html=True)
    if st.button("← Back to Home", key="back"):
        _go("landing")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(FOOTER, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
def _render_result(result: dict):
    vulns  = result.get("vulnerabilities", [])
    files  = result.get("files_scanned", 0)
    target = result.get("target", "")
    risk   = "HIGH" if len(vulns) > 2 else ("MEDIUM" if vulns else "SAFE")
    rcol   = {"HIGH": "#fc8181", "MEDIUM": "#f6ad55", "SAFE": "#68d391"}[risk]

    st.markdown(f"""
    <div class='result-reveal'>
    <h3 style="color:#e2e8f0;margin-bottom:1.25rem;">📋 Scan Report</h3>
    <div class="grid-4" style="margin-bottom:1.5rem;">
        <div class="metric-card"><div class="metric-val" style="color:#63b3ed;font-size:2rem;">{files}</div><div class="metric-lbl">Files Scanned</div></div>
        <div class="metric-card"><div class="metric-val" style="color:#fc8181;font-size:2rem;">{len(vulns)}</div><div class="metric-lbl">Vulnerabilities</div></div>
        <div class="metric-card"><div class="metric-val" style="color:#68d391;font-size:2rem;">{files - len(vulns)}</div><div class="metric-lbl">Clean Files</div></div>
        <div class="metric-card"><div class="metric-val" style="color:{rcol};font-size:1.4rem;">{risk}</div><div class="metric-lbl">Risk Level</div></div>
    </div>
    </div>""", unsafe_allow_html=True)

    if vulns:
        st.markdown("#### 🚨 Vulnerabilities Detected", unsafe_allow_html=True)
        df = pd.DataFrame(vulns)
        df.columns = ["File", "Type", "Confidence"]
        df["Confidence"] = df["Confidence"].apply(lambda x: f"{x*100:.1f}%")
        df["Risk"] = df["Type"].apply(
            lambda v: "🔴 HIGH" if v in ["SQL Injection", "Command Injection"] else "🟡 MEDIUM"
        )
        st.dataframe(df[["File", "Type", "Risk", "Confidence"]], use_container_width=True, hide_index=True)
    else:
        st.markdown("""
        <div style="background:rgba(104,211,145,.07);border:1px solid rgba(104,211,145,.2);
             border-radius:14px;padding:2rem;text-align:center;margin-top:1rem;">
            <div style="font-size:2.5rem">✅</div>
            <h3 style="color:#68d391;margin:.5rem 0 .25rem;">No Vulnerabilities Found!</h3>
            <p style="color:#64748b">All scanned code appears to be clean.</p>
        </div>""", unsafe_allow_html=True)


def page_dashboard():
    if not st.session_state.user:
        _go("login")
        return

    user  = st.session_state.user
    email = user.user.email
    uid   = user.user.id
    fname = email.split("@")[0].title()
    ready_badge = (
        '<span style="background:rgba(104,211,145,.1);border:1px solid rgba(104,211,145,.25);'
        'border-radius:6px;padding:.2rem .65rem;font-size:.75rem;color:#68d391;margin-left:.75rem;">✅ AI Ready</span>'
        if engine_ready else
        '<span style="color:#fc8181;font-size:.75rem;margin-left:.75rem;">⚠️ AI engine offline</span>'
    )

    # ── Navbar ────────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="navbar">
        <div class="nav-logo">🔐 <span>VulnScanner AI</span></div>
        <div class="nav-right">
            <span style="color:#e2e8f0;">{email}</span>
        </div>
    </div>""", unsafe_allow_html=True)

    # Logout button pinned top-right
    st.markdown("<div style='position:fixed;top:.85rem;right:2.5rem;z-index:1001;'>", unsafe_allow_html=True)
    if st.button("Logout", key="nav_logout"):
        _logout()
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Welcome banner ────────────────────────────────────────────────────────
    st.markdown(f"""
    <div style="padding:2.5rem 3rem 1.5rem;position:relative;z-index:1;">
        <div style="font-size:1.75rem;font-weight:800;color:#e2e8f0;">
            👋 Welcome, <span style="background:linear-gradient(135deg,#63b3ed,#9f7aea);
            -webkit-background-clip:text;-webkit-text-fill-color:transparent;
            background-clip:text;">{fname}</span>
            {ready_badge}
        </div>
        <p style="color:#64748b;margin-top:.35rem;font-size:.95rem;">
            Scan a repository or paste Python code to detect security vulnerabilities.
        </p>
    </div>""", unsafe_allow_html=True)

    # ── Scan panel ────────────────────────────────────────────────────────────
    st.markdown("<div style='padding:0 3rem 2rem;position:relative;z-index:10;'>", unsafe_allow_html=True)
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)

    tab_gh, tab_code = st.tabs(["🐙  GitHub Repository", "📄  Paste Python Code"])

    # GitHub tab
    with tab_gh:
        st.markdown("<p style='color:#64748b;font-size:.875rem;margin-bottom:.5rem;'>Enter a public GitHub repository URL</p>", unsafe_allow_html=True)
        gh_url = st.text_input("GitHub URL", placeholder="https://github.com/username/repo",
                                label_visibility="collapsed", key="gh_url")
        if st.button("🔍  Scan Repository", key="btn_gh"):
            if not gh_url.strip():
                st.error("Please enter a repository URL.")
            elif not gh_url.strip().startswith("https://github.com/"):
                st.error("Only https://github.com/ URLs are supported.")
            elif not engine_ready:
                st.error("AI engine is not loaded. Please restart the app.")
            else:
                with st.spinner("🔐 Cloning & scanning repository..."):
                    try:
                        result = scanner.get_scan_results(gh_url.strip())
                        st.session_state.last_result = result
                        _save(result["target"], result["files_scanned"],
                              len(result["vulnerabilities"]), result["vulnerabilities"])
                        st.success(f"✅ Scan complete — {result['files_scanned']} files scanned.")
                        st.rerun()
                    except ValueError as e:
                        st.error(f"❌ {e}")
                    except Exception as e:
                        st.error(f"❌ Scan failed: {e}")

    # Code tab
    with tab_code:
        st.markdown("<p style='color:#64748b;font-size:.875rem;margin-bottom:.5rem;'>Paste Python code to analyse for vulnerabilities</p>", unsafe_allow_html=True)
        code_in = st.text_area("Code", placeholder="# Paste your Python code here...",
                                height=220, label_visibility="collapsed", key="code_in")
        if st.button("🔍  Analyse Code", key="btn_code"):
            if not code_in.strip():
                st.error("Please paste some code first.")
            elif not engine_ready:
                st.error("AI engine is not loaded. Please restart the app.")
            else:
                with st.spinner("🧠 Running AI vulnerability analysis..."):
                    try:
                        vuln_type, confidence = scanner.engine.scan_code_snippet(code_in.strip())
                        vulns = (
                            [{"file": "pasted_snippet.py", "vulnerability": vuln_type, "confidence": confidence}]
                            if vuln_type != "Safe Code" else []
                        )
                        result = {"target": "Pasted Code", "files_scanned": 1, "vulnerabilities": vulns}
                        st.session_state.last_result = result
                        _save("Pasted Code", 1, len(vulns), vulns)
                        st.success("✅ Analysis complete!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Analysis failed: {e}")

    st.markdown("</div>", unsafe_allow_html=True)  # close glass-card
    st.markdown("</div>", unsafe_allow_html=True)  # close padding div

    # ── Scan result ───────────────────────────────────────────────────────────
    if st.session_state.last_result:
        st.markdown("<div style='padding:0 3rem 2rem;position:relative;z-index:1;'>", unsafe_allow_html=True)
        _render_result(st.session_state.last_result)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="padding:0 3rem 2rem;position:relative;z-index:1;">
            <div style="background:rgba(255,255,255,.02);border:1px dashed rgba(255,255,255,.1);
                 border-radius:16px;padding:2.5rem;text-align:center;color:#334155;">
                <div style="font-size:2rem;margin-bottom:.5rem;">🔍</div>
                <div style="font-size:.95rem;">Your scan results will appear here</div>
            </div>
        </div>""", unsafe_allow_html=True)

    # ── Scan history ──────────────────────────────────────────────────────────
    st.markdown("<div style='padding:0 3rem 3rem;position:relative;z-index:1;'>", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("### 📋 Scan History")
    try:
        rows = supabase.table("scans").select("*").eq("user_id", uid)\
               .order("created_at", desc=True).limit(20).execute().data
        if not rows:
            st.info("No scans yet — run your first scan above!")
        else:
            df = pd.DataFrame(rows)[["created_at","target","files_scanned","vulnerabilities_found"]]
            df.columns = ["Date", "Target", "Files Scanned", "Vulnerabilities"]
            df["Date"] = pd.to_datetime(df["Date"]).dt.strftime("%b %d %Y  %H:%M")
            st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        st.warning(f"Could not load history: {e}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(FOOTER, unsafe_allow_html=True)


# ── Router ─────────────────────────────────────────────────────────────────────
_p = st.session_state.page
if   _p == "landing":   page_landing()
elif _p == "login":     page_login()
elif _p == "dashboard": page_dashboard()
else:                   _go("landing")
