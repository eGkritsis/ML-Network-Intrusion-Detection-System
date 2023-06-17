import pandas as pd
import matplotlib.pyplot as plt

# Set pandas display options to show all columns and rows
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# Load the dataset
dataset = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
dataset = dataset.drop(['id', 'label', 'attack_cat'], axis=1)

# Select only the numeric columns
numeric_columns = dataset.select_dtypes(include='number')

# Calculate the correlation matrix
correlation_matrix = numeric_columns.corr()

print(correlation_matrix)

# Plot the correlation matrix
plt.figure(figsize=(12, 10))
plt.imshow(correlation_matrix, cmap='coolwarm', interpolation='nearest')
plt.colorbar()
plt.xticks(range(len(correlation_matrix.columns)), correlation_matrix.columns, rotation=90)
plt.yticks(range(len(correlation_matrix.columns)), correlation_matrix.columns)
plt.title('Data Correlation')
plt.show()

''' 
spkts and dpkts (correlation coefficient: 0.97)
sbytes and dbytes (correlation coefficient: 0.99)
sloss and spkts (correlation coefficient: 0.97)
dloss and dpkts (correlation coefficient: 0.98)
sload and dload (correlation coefficient: -0.92)
stcpb and swin (correlation coefficient: 0.75)
dtcpb and dwin (correlation coefficient: 0.77)
'''
