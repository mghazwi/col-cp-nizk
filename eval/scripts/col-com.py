import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('compiled_results_median.csv')

df_total = df[df['phase'] == 'total_stats']

x_values = [2**i for i in range(1, 7)]

share_times = []
commit_times = []

for x in x_values:
    share_time = df_total.loc[df_total['title'] == f'share_and_commit/{x}/1', 'Total Time'].iloc[0] / 1000
    commit_time = df_total.loc[df_total['title'] == f'commit_and_share/{x}/1', 'Total Time'].iloc[0] / 1000
    share_times.append(share_time)
    commit_times.append(commit_time)

plt.figure()
plt.plot(x_values, share_times, marker='o', label='share_and_commit')
plt.plot(x_values, commit_times, marker='o', label='commit_and_share')
plt.xlabel('x', fontsize=24)
plt.ylabel('Time (ms)', fontsize=24)
plt.xticks(fontsize=24)
plt.yticks(fontsize=24)
plt.legend(fontsize=24)
plt.xscale('log', base=2)
plt.yscale('log', base=2)
plt.show()