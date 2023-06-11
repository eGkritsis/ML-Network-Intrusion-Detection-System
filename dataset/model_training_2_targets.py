import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import OrdinalEncoder
import joblib

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" column from the training dataset
train_set = train_set.drop(["id"], axis=1)

# Drop the "id" column from the test dataset
test_set = test_set.drop(["id"], axis=1)

# Separate features and labels
x_train = train_set.drop(["label", "attack_cat"], axis=1)
y_train = train_set[["label", "attack_cat"]]

x_test = test_set.drop(["label", "attack_cat"], axis=1)
y_test = test_set[["label", "attack_cat"]]

# Fit ordinal encoder on combined training and test sets and transform both sets
ordinal_encoder = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
categorical_features = ['proto', 'service', 'state']

# Fit ordinal encoder on training set
ordinal_encoder.fit(x_train[categorical_features])

# Transform both training and test sets using the fitted ordinal encoder
x_train_encoded = x_train.copy()
x_train_encoded[categorical_features] = ordinal_encoder.transform(x_train[categorical_features])

x_test_encoded = x_test.copy()
x_test_encoded[categorical_features] = ordinal_encoder.transform(x_test[categorical_features])

# Fit ordinal encoder on training set for label and attack_cat and transform training and test sets
ordinal_encoder.fit(y_train)

y_train_encoded = y_train.copy()
y_train_encoded = ordinal_encoder.transform(y_train)

y_test_encoded = y_test.copy()
y_test_encoded = ordinal_encoder.transform(y_test)

# Create a Random Forest classifier
rf = RandomForestClassifier()

# Train the model
rf.fit(x_train_encoded, y_train_encoded)

# Make predictions on the test set
predictions_encoded = rf.predict(x_test_encoded)

# Convert the predictions back to the original labels
predictions = ordinal_encoder.inverse_transform(predictions_encoded)

# Create separate DataFrames for each target variable
predictions_df_label = pd.DataFrame(predictions[:, 0], columns=["predicted_label"])
predictions_df_attack_cat = pd.DataFrame(predictions[:, 1], columns=["predicted_attack_cat"])

# Convert the predicted labels back to the original data type
predictions_df_label["predicted_label"] = predictions_df_label["predicted_label"].astype(str)
predictions_df_attack_cat["predicted_attack_cat"] = predictions_df_attack_cat["predicted_attack_cat"].astype(str)

# Evaluate the model for each target variable
report_label = classification_report(y_test["label"].astype(str), predictions_df_label["predicted_label"])
report_attack_cat = classification_report(y_test["attack_cat"].astype(str), predictions_df_attack_cat["predicted_attack_cat"])

# Print the classification reports
print("Classification Report for label:")
print(report_label)
print("Classification Report for attack_cat:")
print(report_attack_cat)

# Save the trained model as a .pkl file
joblib.dump(rf, 'model_label_attack_cat.pkl')

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
print(proto_counts)

# Value counts for 'service'
service_counts = train_set['service'].value_counts().head(100).to_dict()
print("service")
print(service_counts)

# Value counts for 'state'
state_counts = train_set['state'].value_counts().head(100).to_dict()
print("state")
print(state_counts)


'''
Classification Report for label:
              precision    recall  f1-score   support

           0       0.77      0.98      0.86     56000
           1       0.99      0.86      0.92    119341

    accuracy                           0.90    175341
   macro avg       0.88      0.92      0.89    175341
weighted avg       0.92      0.90      0.90    175341

Classification Report for attack_cat:
                precision    recall  f1-score   support

      Analysis       0.00      0.00      0.00      2000
      Backdoor       0.97      0.03      0.07      1746
           DoS       0.34      0.54      0.42     12264
      Exploits       0.74      0.62      0.68     33393
       Fuzzers       0.61      0.11      0.19     18184
       Generic       0.93      0.98      0.96     40000
        Normal       0.75      0.99      0.85     56000
Reconnaissance       0.92      0.72      0.81     10491
     Shellcode       0.49      0.49      0.49      1133
         Worms       0.76      0.12      0.21       130

      accuracy                           0.75    175341
     macro avg       0.65      0.46      0.47    175341
  weighted avg       0.75      0.75      0.72    175341
  '''