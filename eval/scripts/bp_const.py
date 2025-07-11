import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 24

df = pd.read_csv('compiled_results_median.csv')

prov_df = df[df['phase'] == 'proving_stats'].copy()

prov_df['Constraints'] = prov_df['title'].apply(lambda t: int(t.split('/')[-1]))

bp_prefix = 'bp_r1cs_link_bench/2/'
subset = df[df['title'].str.startswith(bp_prefix)]
pivot_df = subset.pivot(index='title', columns='phase', values='Total Time').reset_index()
pivot_df['Constraints'] = pivot_df['title'].apply(lambda t: int(t.split('/')[-1]))
pivot_df['Total Time'] = pivot_df['proving_stats'] + pivot_df['link_stats']
cp_df = pivot_df[['Constraints', 'Total Time']]

schemes = {
    'single_bp/1/': (
        'bp (single prover)',
        prov_df[prov_df['title'].str.startswith('single_bp/1/')]
    ),
    'bp_r1cs_link_bench/2/': (
        'col-bp',
        prov_df[prov_df['title'].str.startswith(bp_prefix)]
    ),
    'col-cp-bp': (
        'col-cp-bp',
        cp_df
    ),
}

plt.figure(figsize=plt.rcParams['figure.figsize'])
for prefix, (label, subdf) in schemes.items():
    subdf_sorted = subdf.sort_values('Constraints')
    plt.plot(subdf_sorted['Constraints'], subdf_sorted['Total Time'], marker='o', label=label)

plt.xscale('log', base=2)
plt.yscale('log', base=2)

plt.xlabel('Constraints')
plt.ylabel('Time (ms)')
plt.legend()
plt.tight_layout()
plt.show()
