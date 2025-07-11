import pandas as pd
import matplotlib.pyplot as plt
import re

plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 24

df = pd.read_csv('compiled_results_median.csv')

mask_bp = (
    (df['phase'] == 'proving_stats') &
    df['title'].str.match(r'^bp_r1cs_link_bench/(\d+)/1024$')
)
mask_leg = (
    (df['phase'] == 'proving_stats') &
    df['title'].str.match(r'^legogroth/(\d+)/1024$')
)
df = pd.concat([df[mask_bp], df[mask_leg]]).copy()

df['x'] = df['title'].str.extract(r'/(\d+)/1024$')[0].astype(int)

df['time_ms'] = df['Total Time'] / 1000

bp = df[df['title'].str.startswith('bp_r1cs_link_bench')].sort_values('x')
lego = df[df['title'].str.startswith('legogroth')].sort_values('x')


plt.plot(bp['x'], bp['time_ms'], marker='o', label='col-cp-bp')
plt.plot(lego['x'], lego['time_ms'], marker='s', label='col-cp-gro16')

plt.xlabel('Provers',   fontsize=24)
plt.ylabel('Time (ms)', fontsize=24)
plt.xscale('log', base=2)
plt.yscale('log', base=2)

plt.legend(fontsize=24)
plt.tight_layout()
plt.show()
