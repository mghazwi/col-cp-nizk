import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 24

df = pd.read_csv('compiled_results_median.csv')

prov_df = df[df['phase'] == 'proving_stats'].copy()

prov_df['Constraints'] = prov_df['title'].apply(lambda t: int(t.split('/')[-1]))

schemes = {
    'single_groth/1/': ('gro16 (single prover)', prov_df[prov_df['title'].str.startswith('single_groth/1/')]),
    'groth/2/': ('col-gro16 (OB22)', prov_df[prov_df['title'].str.startswith('groth/2/')]),
    'legogroth/2/': ('col-cp-gro16', prov_df[prov_df['title'].str.startswith('legogroth/2/')]),
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