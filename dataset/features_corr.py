import pandas as pd
import matplotlib.pyplot as plt

# Set pandas display options to show all columns and rows
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# Load the dataset
dataset = pd.read_csv(r'..\Network-Traffic-Analyzer\dataset\MTA-KDD-19-master\datasetLegitimate33features.csv')
dataset = dataset.drop(['Start_flow', 'DeltaTimeFlow', 'label'], axis=1)

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