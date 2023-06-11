import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import classification_report
import joblib

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" and "attack_cat" columns from the training dataset
train_set = train_set.drop(["id", "attack_cat"], axis=1)

# Drop the "id" and "attack_cat" columns from the test dataset
test_set = test_set.drop(["id", "attack_cat"], axis=1)

# Combine the training and test sets for ordinal encoding
combined_set = pd.concat([train_set, test_set], axis=0)

# Apply ordinal encoding to categorical features
ordinal_encoder = OrdinalEncoder()
categorical_features = ['proto', 'service', 'state']

# Create a mapping dictionary for inverse transformation
mapping_dict = {}

for feature in categorical_features:
    # Fit ordinal encoder on combined training and test sets
    ordinal_encoder.fit(combined_set[[feature]])
    
    # Transform training set using the fitted ordinal encoder
    train_set[feature] = ordinal_encoder.transform(train_set[[feature]])
    
    # Transform test set using the fitted ordinal encoder
    test_set[feature] = ordinal_encoder.transform(test_set[[feature]])
    
    # Create a mapping dictionary for inverse transformation
    mapping_dict[feature] = dict(zip(ordinal_encoder.transform(combined_set[[feature]]).flatten(), combined_set[feature]))

# Separate features and labels
x_train = train_set.drop("label", axis=1)  # Drop the 'label' column from the training dataset
y_train = train_set["label"]  # Target variable for training the data

x_test = test_set.drop("label", axis=1)
y_test = test_set["label"]

# Create a Naive Bayes classifier
nb = GaussianNB()

# Train the model
nb.fit(x_train, y_train)

# Make predictions on the test set
predictions = nb.predict(x_test)

# Evaluate the model
report = classification_report(y_test, predictions)
print(report)

# Save the trained model as a .pkl file
joblib.dump(nb, 'naive_label.pkl')


'''
precision    recall  f1-score   support

           0       0.63      0.71      0.67     56000
           1       0.85      0.80      0.83    119341

    accuracy                           0.77    175341
   macro avg       0.74      0.76      0.75    175341
weighted avg       0.78      0.77      0.78    175341
'''