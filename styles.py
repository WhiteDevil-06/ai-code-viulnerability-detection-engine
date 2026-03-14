# ============================================================
# styles.py — VulnScanner AI
# All UI constants: CSS, Particle HTML
# Exports: GLOBAL_CSS, PARTICLES_HTML
# ============================================================

PARTICLES_HTML = """
<div class="particles-bg">
  <div class="particle p1"></div><div class="particle p2"></div>
  <div class="particle p3"></div><div class="particle p4"></div>
  <div class="particle p5"></div><div class="particle p6"></div>
  <div class="particle p7"></div><div class="particle p8"></div>
  <div class="particle p9"></div><div class="particle p10"></div>
  <div class="particle p11"></div><div class="particle p12"></div>
  <div class="particle p13"></div><div class="particle p14"></div>
  <div class="particle p15"></div>
</div>
"""

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&display=swap');

/* ── Reset ──────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
    background-color: #0a0e1a;
    color: #e2e8f0;
}

body {
    background: linear-gradient(-45deg, #0a0e1a, #0d1b2a, #0f172a, #080c18) !important;
    background-size: 400% 400% !important;
    animation: bgShift 20s ease infinite !important;
}

@keyframes bgShift {
    0%, 100% { background-position: 0% 50%; }
    50%       { background-position: 100% 50%; }
}

/* ── Scrollbar ──────────────────────────────────────────── */
::-webkit-scrollbar              { width: 8px; height: 8px; }
::-webkit-scrollbar-track        { background: #0a0e1a; }
::-webkit-scrollbar-thumb        { background: #1e293b; border-radius: 6px; border: 2px solid #0a0e1a; }
::-webkit-scrollbar-thumb:hover  { background: #334155; }

/* ── Hide Streamlit chrome ──────────────────────────────── */
header[data-testid="stHeader"], footer, #MainMenu,
[data-testid="stDecoration"], section[data-testid="stSidebar"] { display: none !important; }

.block-container { padding: 0 !important; max-width: 100% !important; }

/* ── Particles ──────────────────────────────────────────── */
.particles-bg {
    position: fixed; top: 0; left: 0;
    width: 100vw; height: 100vh;
    overflow: hidden; z-index: 0; pointer-events: none;
}
.particle { position: absolute; border-radius: 50%; animation: floatUp linear infinite; }

@keyframes floatUp {
    0%   { transform: translateY(110vh) scale(0); opacity: 0; }
    5%   { opacity: 1; }
    90%  { opacity: 0.5; }
    100% { transform: translateY(-10vh) scale(1.2); opacity: 0; }
}
.p1  { width:3px; height:3px; left:5%;  background:rgba(99,179,237,.6); animation-duration:12s; animation-delay:0s;   }
.p2  { width:5px; height:5px; left:10%; background:rgba(159,122,234,.5);animation-duration:8s;  animation-delay:-4s;  }
.p3  { width:2px; height:2px; left:18%; background:rgba(99,179,237,.4); animation-duration:15s; animation-delay:-8s;  }
.p4  { width:4px; height:4px; left:25%; background:rgba(66,153,225,.6); animation-duration:10s; animation-delay:-2s;  }
.p5  { width:3px; height:3px; left:32%; background:rgba(129,140,248,.5);animation-duration:13s; animation-delay:-6s;  }
.p6  { width:6px; height:6px; left:40%; background:rgba(99,179,237,.3); animation-duration:9s;  animation-delay:-1s;  }
.p7  { width:2px; height:2px; left:48%; background:rgba(159,122,234,.6);animation-duration:11s; animation-delay:-9s;  }
.p8  { width:4px; height:4px; left:55%; background:rgba(99,179,237,.5); animation-duration:14s; animation-delay:-3s;  }
.p9  { width:3px; height:3px; left:62%; background:rgba(66,153,225,.4); animation-duration:8s;  animation-delay:-7s;  }
.p10 { width:5px; height:5px; left:70%; background:rgba(129,140,248,.5);animation-duration:16s; animation-delay:-5s;  }
.p11 { width:2px; height:2px; left:77%; background:rgba(99,179,237,.7); animation-duration:10s; animation-delay:-11s; }
.p12 { width:4px; height:4px; left:82%; background:rgba(159,122,234,.4);animation-duration:12s; animation-delay:-4s;  }
.p13 { width:3px; height:3px; left:87%; background:rgba(66,153,225,.6); animation-duration:9s;  animation-delay:-2s;  }
.p14 { width:6px; height:6px; left:92%; background:rgba(99,179,237,.3); animation-duration:17s; animation-delay:-8s;  }
.p15 { width:2px; height:2px; left:97%; background:rgba(129,140,248,.7);animation-duration:11s; animation-delay:-6s;  }

/* ── Navbar ─────────────────────────────────────────────── */
.navbar {
    position: sticky; top: 0; z-index: 1000;
    display: flex; align-items: center; justify-content: space-between;
    padding: 1rem 2.5rem;
    background: rgba(10,14,26,.92);
    backdrop-filter: blur(20px);
    border-bottom: 1px solid rgba(99,179,237,.1);
    box-shadow: 0 4px 24px rgba(0,0,0,.3);
}
.nav-logo {
    font-size: 1.25rem; font-weight: 800;
    color: #e2e8f0; display: flex; align-items: center; gap: .5rem;
}
.nav-logo span {
    background: linear-gradient(135deg, #63b3ed, #9f7aea);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
}
.nav-right {
    display: flex; align-items: center; gap: 1.25rem;
    font-size: .875rem; color: #64748b;
}

/* ── Hero ───────────────────────────────────────────────── */
.hero-wrap {
    padding: 7rem 2rem 4rem;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    text-align: center;
    position: relative; z-index: 1;
}
.hero-badge {
    display: inline-flex; align-items: center; gap: .5rem;
    padding: .5rem 1.5rem;
    border: 1px solid rgba(99,179,237,.3);
    background: rgba(99,179,237,.08);
    border-radius: 50px; font-size: .78rem; font-weight: 700;
    color: #63b3ed; letter-spacing: 2px; text-transform: uppercase;
    margin-bottom: 2rem; animation: fadeUp .8s ease both;
}
.hero-title {
    font-size: clamp(2.8rem, 7vw, 5.5rem);
    font-weight: 900; line-height: 1.05; letter-spacing: -2px;
    margin-bottom: 1.5rem;
    background: linear-gradient(135deg, #ffffff 0%, #63b3ed 45%, #9f7aea 90%);
    background-size: 200% auto;
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    animation: gradShift 5s ease infinite, fadeUp .8s ease .1s both;
}
@keyframes gradShift {
    0%,100% { background-position: 0% center; }
    50%     { background-position: 100% center; }
}
.hero-sub {
    font-size: 1.1rem; color: #94a3b8;
    max-width: 600px; line-height: 1.9;
    margin-bottom: 2.5rem;
    animation: fadeUp .8s ease .25s both;
}
@keyframes fadeUp {
    from { opacity: 0; transform: translateY(28px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* ── Sections ───────────────────────────────────────────── */
.section-wrap { padding: 3.5rem 2.5rem; position: relative; z-index: 1; }
.section-title {
    font-size: 1.9rem; font-weight: 800; color: #e2e8f0;
    text-align: center; margin-bottom: .4rem;
}
.section-sub  { font-size: .95rem; color: #64748b; text-align: center; margin-bottom: 2.5rem; }

/* ── Glass Cards ────────────────────────────────────────── */
.glass-card {
    background: rgba(13, 20, 40, 0.82);
    backdrop-filter: blur(22px);
    border: 1px solid rgba(255,255,255,.09);
    border-top: 1px solid rgba(255,255,255,.18);
    border-radius: 22px; padding: 2.5rem;
    box-shadow: 0 20px 50px rgba(0,0,0,.5);
    transition: transform .35s ease, box-shadow .35s ease;
    position: relative; z-index: 10;
}
.glass-card:hover {
    transform: translateY(-6px);
    box-shadow: 0 28px 60px rgba(0,0,0,.6), 0 0 40px rgba(66,153,225,.12);
}

/* ── Feature / Step Cards ───────────────────────────────── */
.feat-card, .step-card {
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(255,255,255,.07);
    border-radius: 16px; padding: 2rem;
    text-align: center;
    transition: transform .3s, border-color .3s, background .3s;
    animation: fadeUp .8s ease both;
}
.feat-card:hover, .step-card:hover {
    border-color: rgba(99,179,237,.3);
    background: rgba(99,179,237,.04);
    transform: translateY(-5px);
    box-shadow: 0 12px 32px rgba(0,0,0,.25);
}
.feat-icon  { font-size: 2.2rem; margin-bottom: .7rem; }
.feat-title { font-size: 1rem; font-weight: 700; color: #e2e8f0; margin-bottom: .35rem; }
.feat-desc  { font-size: .875rem; color: #64748b; line-height: 1.7; }

.step-num {
    display: inline-flex; align-items: center; justify-content: center;
    width: 40px; height: 40px; border-radius: 50%;
    background: linear-gradient(135deg, #3182ce, #6366f1);
    font-size: .95rem; font-weight: 900; color: #fff; margin-bottom: 1rem;
}
.step-title { font-size: 1rem; font-weight: 700; color: #e2e8f0; margin-bottom: .35rem; }
.step-desc  { font-size: .85rem; color: #64748b; line-height: 1.6; }

/* ── Metric Cards ───────────────────────────────────────── */
.metric-card {
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(255,255,255,.06);
    border-radius: 14px; padding: 1.5rem; text-align: center;
    animation: fadeUp .8s ease both;
}
.metric-val {
    font-size: 2.6rem; font-weight: 900;
    background: linear-gradient(135deg, #63b3ed, #9f7aea);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    animation: glowPulse 3s ease infinite;
}
@keyframes glowPulse {
    0%,100% { filter: drop-shadow(0 0 4px rgba(99,179,237,.3)); }
    50%     { filter: drop-shadow(0 0 16px rgba(99,179,237,.65)); }
}
.metric-lbl { font-size: .72rem; color: #475569; text-transform: uppercase; letter-spacing: 1.5px; margin-top: .25rem; }

/* ── Buttons ────────────────────────────────────────────── */
div[data-testid="stButton"] > button {
    font-family: 'Inter', sans-serif !important;
    font-weight: 800 !important;
    font-size: 1rem !important;
    border-radius: 12px !important;
    padding: .85rem 2.5rem !important;
    border: none !important;
    background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%) !important;
    color: #fff !important;
    box-shadow: 0 8px 20px rgba(37,99,235,.35) !important;
    transition: all .35s cubic-bezier(.16,1,.3,1) !important;
    width: auto !important;
    min-width: 220px !important;
    display: block !important;
    margin: 0 auto !important;
}

div[data-testid="stButton"] > button:hover {
    transform: translateY(-4px) scale(1.04) !important;
    box-shadow: 0 18px 40px rgba(37,99,235,.55) !important;
    filter: brightness(1.15) !important;
}

div[data-testid="stButton"] > button:active {
    transform: translateY(-1px) !important;
}

/* Center all Streamlit button containers */
div.stButton {
    display: flex !important;
    justify-content: center !important;
    width: 100% !important;
    margin: 1rem 0 !important;
}

/* ── Inputs ─────────────────────────────────────────────── */
div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea {
    background: rgba(15,23,42,.8) !important;
    border: 1px solid rgba(99,179,237,.2) !important;
    border-radius: 10px !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: .95rem !important;
    transition: border-color .25s, box-shadow .25s !important;
}
div[data-testid="stTextInput"] input:focus,
div[data-testid="stTextArea"] textarea:focus {
    border-color: #4299e1 !important;
    box-shadow: 0 0 0 3px rgba(66,153,225,.18) !important;
    outline: none !important;
}

/* ── Tabs ───────────────────────────────────────────────── */
div[data-testid="stTabs"] [data-baseweb="tab-list"] { background: transparent !important; gap: 0 !important; }
div[data-testid="stTabs"] [data-baseweb="tab"] {
    background: transparent !important; color: #64748b !important;
    font-weight: 600 !important; font-family: 'Inter', sans-serif !important;
    border-radius: 0 !important; border: none !important;
    padding: .75rem 1.5rem !important; transition: color .25s !important;
}
div[data-testid="stTabs"] [aria-selected="true"] {
    color: #63b3ed !important;
    border-bottom: 2px solid #4299e1 !important;
}

/* ── DataFrames ─────────────────────────────────────────── */
div[data-testid="stDataFrame"] {
    border-radius: 14px !important;
    border: 1px solid rgba(255,255,255,.08) !important;
    overflow: hidden !important;
}

/* ── Grids ──────────────────────────────────────────────── */
.grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1.5rem;
    width: 100%;
    margin: 0 auto;
}
.grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1.25rem;
    width: 100%;
    margin: 0 auto;
}
@media (max-width: 992px) {
    .grid-3, .grid-4 { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 600px) {
    .grid-3, .grid-4 { grid-template-columns: 1fr; }
}

/* ── Centering ──────────────────────────────────────────── */
.auth-center {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 0 1rem;
}

/* ── Misc ───────────────────────────────────────────────── */
hr { border-color: rgba(255,255,255,.07) !important; margin: 2.5rem 0 !important; }
.result-reveal { animation: fadeUp .6s ease; }

/* ── Footer ─────────────────────────────────────────────── */
.footer {
    padding: 2.5rem 2rem;
    text-align: center;
    color: #475569;
    font-size: .875rem;
    background: rgba(8, 12, 24, 0.95);
    border-top: 1px solid rgba(255,255,255,.06);
    margin-top: 5rem;
    position: relative; z-index: 1;
    backdrop-filter: blur(8px);
}
.footer b  { color: #63b3ed; font-weight: 700; }
.footer em { color: #334155; }
</style>
"""
