import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import classification_report
import joblib

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" and "attack_cat" column from the training dataset
train_set = train_set.drop(["id", "attack_cat"], axis=1)

# Drop the "id" and "attack_cat" column from the test dataset
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
x_train = train_set.drop("label", axis=1) # Drop the label column from the training dataset
y_train = train_set["label"] # Target variable for training the data 

x_test = test_set.drop("label", axis=1) 
y_test = test_set["label"]

# Train the Random Forest model
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(x_train, y_train)

# Make predictions on the test set
predictions = rf.predict(x_test)

# Evaluate the model
report = classification_report(y_test, predictions)
print(report)

# Save the trained model as a .pkl file
#joblib.dump(rf, 'model_label.pkl')

# Check feature importances
feature_importances = rf.feature_importances_

# Create a DataFrame to display the feature importances
importance_df = pd.DataFrame({'Feature': x_train.columns, 'Importance': feature_importances})

# Sort the DataFrame by importance in descending order
importance_df = importance_df.sort_values(by='Importance', ascending=False)

# Display the feature importances
print(importance_df)

# Value counts for 'proto'
proto_counts = train_set['proto'].value_counts().head(100).to_dict()
print("proto")
for key, value in proto_counts.items():
    feature_name = mapping_dict['proto'][key]
    print(f"{feature_name}: {value}")

# Value counts for 'service'
service_counts = train_set['service'].value_counts().head(100).to_dict()
print("service")
for key, value in service_counts.items():
    feature_name = mapping_dict['service'][key]
    print(f"{feature_name}: {value}")

# Value counts for 'state'
state_counts = train_set['state'].value_counts().head(100).to_dict()
print("state")
for key, value in state_counts.items():
    feature_name = mapping_dict['state'][key]
    print(f"{feature_name}: {value}")


'''
Without features 'id' and 'attack_cat':

precision    recall  f1-score   support

           0       0.77      0.98      0.86     56000
           1       0.99      0.86      0.92    119341

    accuracy                           0.90    175341
   macro avg       0.88      0.92      0.89    175341
weighted avg       0.92      0.90      0.90    175341

'''