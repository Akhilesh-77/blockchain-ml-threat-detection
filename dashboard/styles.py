"""
Styling module providing custom CSS for Dark SOC Cybersecurity Aesthetic.
"""

SOC_CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

    /* Global Typography and Background */
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
        max-width: 96%;
    }

    /* SOC Header Card */
    .soc-header {
        background: linear-gradient(135deg, #0d1527 0%, #0a0f1d 100%);
        border: 1px solid #1e293b;
        border-left: 4px solid #06b6d4;
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 22px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }

    .soc-header h1 {
        color: #f8fafc;
        font-size: 1.65rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .soc-header p {
        color: #94a3b8;
        font-size: 0.88rem;
        margin: 6px 0 0 0;
    }

    /* Metric Card Styling */
    .soc-metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 16px 20px;
        transition: transform 0.15s ease, border-color 0.15s ease;
        position: relative;
        overflow: hidden;
    }

    .soc-metric-card:hover {
        border-color: #374151;
        transform: translateY(-2px);
    }

    .soc-metric-title {
        color: #9ca3af;
        font-size: 0.78rem;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }

    .soc-metric-value {
        color: #f9fafb;
        font-size: 1.75rem;
        font-weight: 700;
        line-height: 1.1;
    }

    .soc-metric-subtitle {
        color: #6b7280;
        font-size: 0.75rem;
        margin-top: 6px;
    }

    /* Badges */
    .badge-normal {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 3px 9px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    .badge-suspicious {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.35);
        padding: 3px 9px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    .badge-malicious {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        padding: 3px 9px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    .badge-cyan {
        background: rgba(6, 182, 212, 0.15);
        color: #22d3ee;
        border: 1px solid rgba(6, 182, 212, 0.35);
        padding: 3px 9px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    .badge-purple {
        background: rgba(139, 92, 246, 0.15);
        color: #c084fc;
        border: 1px solid rgba(139, 92, 246, 0.35);
        padding: 3px 9px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }

    .badge-source-live {
        background: rgba(6, 182, 212, 0.2);
        color: #38bdf8;
        border: 1px solid #0284c7;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        display: inline-block;
    }

    .badge-source-public {
        background: rgba(139, 92, 246, 0.2);
        color: #c084fc;
        border: 1px solid #7c3aed;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        display: inline-block;
    }

    .badge-source-demo {
        background: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #d97706;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        display: inline-block;
    }

    /* Cryptographic Hash pill */
    .hash-pill {
        background: #0f172a;
        color: #38bdf8;
        border: 1px solid #1e293b;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
    }

    /* Tamper Alert Banners */
    .tamper-alert {
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid #ef4444;
        border-left: 5px solid #ef4444;
        border-radius: 6px;
        padding: 14px 18px;
        color: #fecaca;
        margin: 15px 0;
    }

    .valid-alert {
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid #10b981;
        border-left: 5px solid #10b981;
        border-radius: 6px;
        padding: 14px 18px;
        color: #a7f3d0;
        margin: 15px 0;
    }

    /* Sidebar navigation styling */
    section[data-testid="stSidebar"] {
        background-color: #0b0f19;
        border-right: 1px solid #1f2937;
    }

    /* Table adjustments */
    div[data-testid="stDataFrame"] {
        border: 1px solid #1f2937;
        border-radius: 6px;
    }
</style>
"""


def render_metric_card(title: str, value: str, subtitle: str = "", border_color: str = "#1f2937") -> str:
    """Generate HTML for an executive SOC metric card."""
    return f"""
    <div class="soc-metric-card" style="border-top: 3px solid {border_color};">
        <div class="soc-metric-title">{title}</div>
        <div class="soc-metric-value">{value}</div>
        <div class="soc-metric-subtitle">{subtitle}</div>
    </div>
    """

