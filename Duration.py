import pandas as pd
df = pd.read_csv('results.csv')
avg_duration_per_file_per_tool=df.groupby('toolid')['duration'].mean().reset_index()
sum_duration_per_tool = df.groupby('toolid')['duration'].sum().reset_index()

print("Total Duration")
print(sum_duration_per_tool)

print("Duration per file")
print(avg_duration_per_file_per_tool)