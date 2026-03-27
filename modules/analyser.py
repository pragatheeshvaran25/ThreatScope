# modules/analyser.py
# Job: Calculate risk scores for each finding

import pandas as pd

# How dangerous is each service? (0 = safe, 10 = very dangerous)
SERVICE_RISK = {
    'telnet':     10,   # sends passwords in plain text!
    'rdp':         9,   # main ransomware entry point
    'smb':         9,   # WannaCry attack vector
    'ftp':         8,   # plain text credentials
    'vnc':         8,   # remote access, often misconfigured
    'mongodb':     8,   # no password by default
    'redis':       8,   # no password by default
    'mysql':       7,   # database, should not be public
    'mssql':       7,   # database
    'postgresql':  7,   # database
    'smtp':        4,   # can relay spam
    'ssh':         3,   # encrypted but brute-force target
    'http':        2,   # depends on what's running
    'https':       1,   # safest
}

# Dangerous port numbers
DANGEROUS_PORTS = {
    '21', '23', '135', '139', '445',
    '1433', '3306', '3389', '5900', '6379', '27017'
}

# Countries with higher rates of malicious traffic
HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR', 'NG', 'UA', 'VN', 'RO'}

# What to do about each service
RECOMMENDATIONS = {
    'telnet':     'DISABLE IMMEDIATELY — replace with SSH.',
    'ftp':        'Replace with SFTP. FTP sends passwords in plain text.',
    'rdp':        'Restrict to VPN only. Enable Network Level Authentication.',
    'vnc':        'Set a strong password. Restrict to trusted IPs only.',
    'smb':        'Block port 445 at firewall. Check WannaCry patch.',
    'ssh':        'Use SSH keys instead of passwords.',
    'http':       'Redirect to HTTPS. Check for outdated software.',
    'https':      'Verify TLS version. Check certificate expiry.',
    'mysql':      'Should NOT be internet-facing. Move behind firewall.',
    'postgresql': 'Should NOT be internet-facing. Restrict to localhost.',
    'mssql':      'Restrict to internal network only.',
    'redis':      'Set a password. Bind to localhost only.',
    'mongodb':    'Enable authentication immediately.',
    'smtp':       'Disable open relay. Configure SPF/DKIM.',
}
DEFAULT_REC = 'Review this service and restrict access if not needed.'


def _exposure_score(row) -> float:
    """How dangerous is this service? (0-10)"""
    service = str(row.get('service', '')).lower()
    port    = str(row.get('port', '0'))
    state   = str(row.get('state', 'open')).lower()

    score = SERVICE_RISK.get(service, 0)
    if score == 0 and port in DANGEROUS_PORTS:
        score = 6   # dangerous port even if service unknown
    if score == 0:
        score = 1   # minimum score for any open port
    if state == 'filtered':
        score = score * 0.5   # firewall present, half the risk

    return min(10.0, float(score))


def _threat_score(row) -> float:
    """What does VirusTotal say? (0-10)"""
    malicious  = int(row.get('malicious_reports', 0))
    suspicious = int(row.get('suspicious_count',  0))
    community  = int(row.get('community_score',   0))

    score = (malicious * 2.0) + (suspicious * 0.5)
    if community < 0:
        score += min(2.0, abs(community) * 0.1)

    return min(10.0, score)


def _context_score(row) -> float:
    """Country risk + bad categories (0-10)"""
    score     = 0.0
    country   = str(row.get('country',    '')).upper()
    cats      = str(row.get('categories', '')).lower()
    community = int(row.get('community_score', 0))

    if country in HIGH_RISK_COUNTRIES: score += 3.0
    if 'malware'  in cats:             score += 4.0
    if 'phishing' in cats:             score += 3.0
    if 'spam'     in cats:             score += 2.0
    if 'botnet'   in cats:             score += 3.5
    if community < -5:                 score += 1.0

    return min(10.0, score)


def _get_severity(score: float) -> str:
    """Convert score to label."""
    if score >= 7.0: return 'Critical'
    if score >= 5.0: return 'High'
    if score >= 3.0: return 'Medium'
    return 'Low'


def enrich_dataframe(df: pd.DataFrame, vt_data: dict = None) -> pd.DataFrame:
    """
    Add risk scores to the scan DataFrame.
    vt_data = {ip: {malicious_reports: X, country: Y, ...}}
    """
    df = df.copy()

    # Merge VirusTotal data if provided
    if vt_data:
        vt_df = pd.DataFrame(vt_data).T.rename_axis('ip').reset_index()
        df    = df.merge(vt_df, on='ip', how='left')

    # Fill missing VT columns with safe defaults
    defaults = {
        'malicious_reports': 0, 'suspicious_count': 0,
        'harmless_count': 0,    'community_score': 0,
        'country': 'Unknown',   'network': 'Unknown',
        'categories': ''
    }
    for col, val in defaults.items():
        if col not in df.columns:
            df[col] = val

    # Calculate 3 scores for each row
    df['exposure_score'] = df.apply(_exposure_score, axis=1).round(2)
    df['threat_score']   = df.apply(_threat_score,   axis=1).round(2)
    df['context_score']  = df.apply(_context_score,  axis=1).round(2)

    # Final score = 40% exposure + 40% threat + 20% context
    df['risk_score'] = (
        df['exposure_score'] * 0.40 +
        df['threat_score']   * 0.40 +
        df['context_score']  * 0.20
    ).round(2)

    df['severity']       = df['risk_score'].apply(_get_severity)
    df['recommendation'] = df['service'].apply(
        lambda s: RECOMMENDATIONS.get(str(s).lower(), DEFAULT_REC)
    )
    return df


def get_summary(df: pd.DataFrame) -> dict:
    """Get simple summary stats for the dashboard."""
    crit  = int((df['severity'] == 'Critical').sum())
    high  = int((df['severity'] == 'High').sum())
    vt_flagged = int((df['malicious_reports'] > 0).sum())

    if crit > 0:   posture, colour = 'CRITICAL',  '#dc2626'
    elif high > 0: posture, colour = 'HIGH RISK', '#ea580c'
    elif len(df):  posture, colour = 'MODERATE',  '#d97706'
    else:          posture, colour = 'LOW RISK',  '#16a34a'

    return {
        'total_hosts':  int(df['ip'].nunique()),
        'total_ports':  len(df),
        'critical':     crit,
        'high':         high,
        'vt_flagged':   vt_flagged,
        'max_risk':     float(df['risk_score'].max()) if len(df) else 0,
        'posture':      posture,
        'colour':       colour,
    }