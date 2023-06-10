import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import joblib


# Load the training and test datasets
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')

# Delete rows with proto = icmp or rtp from the test set
test_set = test_set[~test_set['proto'].isin(['icmp', 'rtp'])]

# Delete rows with proto = icmp or rtp from the training set
train_set = train_set[~train_set['proto'].isin(['icmp', 'rtp'])]

# Seperate features and labels
x_train = train_set.drop("label", axis=1) # Drop the label column from the training dataset
y_train = train_set["label"] # Target variable for training the data 

x_test = test_set.drop("label", axis=1) 
y_test = test_set["label"]

# Fit label encoder on training set and transform both training and test sets
label_encoder = LabelEncoder()
categorical_features = ['proto', 'service', 'state', 'attack_cat']

for feature in categorical_features:
    train_set[feature] = label_encoder.fit_transform(train_set[feature])
    test_set[feature] = label_encoder.transform(test_set[feature])

# Retrieve tranformed features and labels
x_train_encoded = train_set.drop("label", axis=1)
y_train_encoded = train_set["label"]

x_test_encoded = test_set.drop("label", axis=1)
y_test_encoded = test_set["label"]

# Create a Random Forest classifier
rf = RandomForestClassifier()

# Train the model
rf.fit(x_train_encoded, y_train_encoded)

# Make predictions on the test set
predictions = rf.predict(x_test_encoded)

# Evaluate the model
report = classification_report(y_test_encoded, predictions)
print(report)

