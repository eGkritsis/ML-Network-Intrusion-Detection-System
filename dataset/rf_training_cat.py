import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import classification_report
import joblib

# Load the training and test datasets
train_set = pd.read_csv(r'..\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'..\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" and "attack_cat" column from the training dataset
train_set = train_set.drop(["id", "label"], axis=1)

# Drop the "id" and "attack_cat" column from the test dataset
test_set = test_set.drop(["id", "label"], axis=1)

# Mapping dictionary for attack category mapping
attack_mapping = {
    'Normal': 'Normal',
    'Backdoor': 'U2R',
    'DoS': 'DoS',
    'Exploits': 'R2L',
    'Fuzzers': 'R2L',
    'Generic': 'R2L',
    'Reconnaissance': 'Probing',
    'Shellcode': 'U2R',
    'Worms': 'DoS',
    'Analysis': 'Probing'
}

# Map the attack categories in the dataset
train_set['attack_cat'] = train_set['attack_cat'].map(attack_mapping)
test_set['attack_cat'] = test_set['attack_cat'].map(attack_mapping)

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

# Separate features and targets
x_train = train_set.drop("attack_cat", axis=1) # Drop the label column from the training dataset
y_train = train_set["attack_cat"] # Target variable for training the data 

x_test = test_set.drop("attack_cat", axis=1) 
y_test = test_set["attack_cat"]

rf = RandomForestClassifier()

# Train the Gradient Boosting model
rf.fit(x_train, y_train)

# Make predictions on the test set
predictions = rf.predict(x_test)

# Evaluate the model
report = classification_report(y_test, predictions)
print(report)

# Save the trained classifier to a pickle file
joblib.dump(rf, 'rf_attack_cat_mapped.pkl')


'''
precision    recall  f1-score   support

         DoS       0.35      0.17      0.23     12394
      Normal       0.76      0.98      0.86     56000
     Probing       0.93      0.60      0.73     12491
         R2L       0.82      0.79      0.81     91577
         U2R       0.52      0.22      0.31      2879

    accuracy                           0.79    175341
   macro avg       0.68      0.55      0.59    175341
weighted avg       0.77      0.79      0.77    175341

'''