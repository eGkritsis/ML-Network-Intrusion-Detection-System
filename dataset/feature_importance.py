import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder

# Load the dataset and split into features and labels
dataset = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
X = dataset.drop(['id', 'label', 'attack_cat'], axis=1)
y = dataset['attack_cat']

# One-hot encode categorical features
categorical_features = ['proto', 'service', 'state']
encoder = OneHotEncoder()
X_encoded = pd.DataFrame(encoder.fit_transform(X[categorical_features]).toarray(), columns=encoder.get_feature_names_out(categorical_features), index=X.index)
X_encoded = pd.concat([X.drop(categorical_features, axis=1), X_encoded], axis=1)

# Create a Random Forest classifier
rf = RandomForestClassifier()

# Train the model
rf.fit(X_encoded, y)

# Get feature importances
importances = rf.feature_importances_

# Sort feature importances in descending order
sorted_indices = importances.argsort()[::-1]
sorted_importances = importances[sorted_indices]

# Get the names of the features in the original order
feature_names = X_encoded.columns.values[sorted_indices]

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
