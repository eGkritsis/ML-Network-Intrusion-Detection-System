import pandas as pd
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.preprocessing import OrdinalEncoder
from sklearn.model_selection import train_test_split

# Load the legitimate traffic dataset
legitimate_dataset = pd.read_csv(r'..\Network-Traffic-Analyzer\dataset\MTA-KDD-19-master\datasetLegitimate33features.csv')

# Load the malware traffic dataset
malware_dataset = pd.read_csv(r'..\Network-Traffic-Analyzer\dataset\MTA-KDD-19-master\datasetMalware33features.csv')

# Merge the datasets
dataset = pd.concat([legitimate_dataset, malware_dataset])

dataset = dataset.drop(['Start_flow', 'DeltaTimeFlow'], axis=1)

# Separate features and target variable
X = dataset.drop('label', axis=1)
y = dataset['label']

# Split the dataset into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)

# Calculate the information gain for each feature
info_gain = mutual_info_classif(X_train, y_train)

# Create a DataFrame to store the feature names and their information gain
feature_info_gain = pd.DataFrame({'Feature': X_train.columns, 'Information Gain': info_gain})

# Sort the DataFrame in descending order of information gain
feature_info_gain = feature_info_gain.sort_values(by='Information Gain', ascending=False)

# Print the feature names and their corresponding information gain
with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    print(feature_info_gain)
