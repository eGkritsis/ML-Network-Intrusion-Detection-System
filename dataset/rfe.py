from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.preprocessing import OrdinalEncoder

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the non-selected features from the training and test sets
train_set = train_set.drop(['id', 'label'], axis=1)
test_set = test_set.drop(['id', 'label'], axis=1)

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

# Create a random forest classifier
rf = RandomForestClassifier()

# Create the RFE object with the random forest classifier and specify the number of features to select
rfe = RFE(estimator=rf, n_features_to_select=30)

# Fit the RFE object to the training data
rfe.fit(x_train, y_train)

# Get the selected features
selected_features = x_train.columns[rfe.support_]

# Print the selected features
print("Selected Features:")
print(selected_features)


''' 
30 features:

'dur', 'proto', 'service', 'state', 'dpkts', 'sbytes', 'dbytes', 'rate',
       'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
       'sjit', 'djit', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
       'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
       'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_srv_dst'

'''

