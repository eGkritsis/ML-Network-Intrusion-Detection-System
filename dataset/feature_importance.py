import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder
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

# Create a Random Forest classifier
rf = RandomForestClassifier()

# Train the model
rf.fit(X_train, y_train)

# Get feature importances
importances = rf.feature_importances_

# Sort feature importances in descending order
sorted_indices = importances.argsort()[::-1]
sorted_importances = importances[sorted_indices]

# Get the names of the features in the original order
feature_names = X_train.columns.values[sorted_indices]

# Print feature importances and sorted feature names
for name, importance in zip(feature_names, sorted_importances):
    print(f"{name}: {importance}")

# Plot the feature importances
plt.figure(figsize=(10, 6))
plt.barh(range(len(feature_names)), sorted_importances, align='center')
plt.yticks(range(len(feature_names)), feature_names)
plt.xlabel('Feature Importance')
plt.ylabel('Features')
plt.title('Random Forest Classifier - Feature Importance')
plt.show()
