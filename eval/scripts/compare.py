import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 24

df = pd.read_csv('compiled_results_median.csv')

constraints = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

prove_bp = []
prove_gro16 = []
setup_gro16 = []

for x in constraints:
    mask_bp = (df['title'] == f'bp_r1cs_link_bench/2/{x}') & (df['phase'] == 'proving_stats')
    bp_vals = df.loc[mask_bp, 'Total Time']
    if bp_vals.empty:
        print(f"Warning: no data for bp_r1cs_link_bench/2/{x} proving_stats; using NaN")
        prove_bp.append(np.nan)
    else:
        prove_bp.append(bp_vals.iloc[0])

    mask_gro_setup = (df['title'] == f'legogroth/2/{x}') & (df['phase'] == 'setup_stats')
    gro_setup_vals = df.loc[mask_gro_setup, 'Total Time']
    if gro_setup_vals.empty:
        print(f"Warning: no data for legogroth/2/{x} setup_stats; using NaN")
        setup_gro16.append(np.nan)
    else:
        setup_gro16.append(gro_setup_vals.iloc[0])

    mask_gro_prove = (df['title'] == f'legogroth/2/{x}') & (df['phase'] == 'proving_stats')
    gro_prove_vals = df.loc[mask_gro_prove, 'Total Time']
    if gro_prove_vals.empty:
        print(f"Warning: no data for legogroth/2/{x} proving_stats; using NaN")
        prove_gro16.append(np.nan)
    else:
        prove_gro16.append(gro_prove_vals.iloc[0])

fig, ax = plt.subplots(figsize=plt.rcParams['figure.figsize'])

x_vals = np.array(constraints)
offset_factor = 0.1
ratio = 2 ** offset_factor
inv_ratio = 2 ** (-offset_factor)
bar_widths = x_vals * (ratio - inv_ratio)

ax.bar(x_vals * inv_ratio, prove_bp, bar_widths,
       label='Prove Time (col-cp-bp)', color='blue')

ax.bar(x_vals * ratio, prove_gro16, bar_widths,
       label='Prove Time (col-cp-gro16)', color='green')
ax.bar(x_vals * ratio, setup_gro16, bar_widths,
       bottom=prove_gro16, label='Setup Time (col-cp-gro16)', color='lightgreen')

ax.set_yscale('log', base=2)
ax.set_xscale('log', base=2)

ax.set_xticks(x_vals)
ax.set_xticklabels([f'$2^{{{int(np.log2(x))}}}$' for x in constraints],
                   fontsize=24)

ax.set_xlabel('Constraints', fontsize=24)
ax.set_ylabel('Time (ms)', fontsize=24)
ax.legend(fontsize=24, loc='upper left')

ax.tick_params(axis='y', labelsize=24)

ax.grid(True, which='both', linestyle='--', axis='y')

plt.tight_layout()
plt.show()
