import pandas as pd
import matplotlib.pyplot as plt
import re

plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 24

df = pd.read_csv('compiled_results_median.csv')

pattern_bp = r'^bp_r1cs_link_bench/2/(\d+)$'
pattern_lego = r'^legogroth/2/(\d+)$'
mask = (
    (df['phase'] == 'total_stats') &
    (df['title'].str.match(pattern_bp) | df['title'].str.match(pattern_lego))
)
df = df[mask].copy()

def extract_x(title):
    m_bp = re.match(pattern_bp, title)
    if m_bp:
        return int(m_bp.group(1))
    m_lg = re.match(pattern_lego, title)
    if m_lg:
        return int(m_lg.group(1))
    return None

df['x'] = df['title'].apply(extract_x)

bp = df[df['title'].str.startswith('bp_r1cs_link_bench')].sort_values('x')
lego = df[df['title'].str.startswith('legogroth')].sort_values('x')

plt.plot(bp['x'], bp['Bytes'], marker='o', label='col-cp-bp')
plt.plot(lego['x'], lego['Bytes'], marker='s', label='col-co-gro16')

plt.xlabel('constraints', fontsize=24)
plt.ylabel('Bytes', fontsize=24)
plt.xscale('log', base=2)
plt.yscale('log', base=2)

plt.legend(fontsize=24)
plt.tight_layout()
plt.show()
