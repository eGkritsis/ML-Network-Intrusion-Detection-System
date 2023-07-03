import pandas as pd
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.preprocessing import OrdinalEncoder

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" and "label" column from the training dataset
train_set = train_set.drop(["id", "label"], axis=1)

# Drop the "id" and "label" column from the test dataset
test_set = test_set.drop(["id", "label"], axis=1)

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
x_train = train_set.drop("attack_cat", axis=1) # Drop the label column from the training dataset
y_train = train_set["attack_cat"] # Target variable for training the data 

x_test = test_set.drop("attack_cat", axis=1) 
y_test = test_set["attack_cat"]

# Calculate the information gain for each feature
info_gain = mutual_info_classif(x_train, y_train)

# Create a DataFrame to store the feature names and their information gain
feature_info_gain = pd.DataFrame({'Feature': x_train.columns, 'Information Gain': info_gain})

# Sort the DataFrame in descending order of information gain
feature_info_gain = feature_info_gain.sort_values(by='Information Gain', ascending=False)

# Print the feature names and their corresponding information gain
with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    print(feature_info_gain)
