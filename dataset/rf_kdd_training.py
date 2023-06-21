import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from sklearn.metrics import classification_report

# Load the legitimate traffic dataset
legitimate_dataset = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\MTA-KDD-19-master\datasetLegitimate33features.csv')

# Load the malware traffic dataset
malware_dataset = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\MTA-KDD-19-master\datasetMalware33features.csv')

# Merge the datasets
dataset = pd.concat([legitimate_dataset, malware_dataset])

# Separate features and target variable
X = dataset.drop('label', axis=1)
y = dataset['label']

# Split the dataset into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)

# Create a Random Forest classifier
rf = RandomForestClassifier()

# Train the model
rf.fit(X_train, y_train)

# Make predictions on the test set
predictions = rf.predict(X_test)

# Evaluate the model
report = classification_report(y_test, predictions)
print(report)

# Save the trained model
#joblib.dump(rf, 'rf_kdd.pkl')


''' 
[21303 rows x 33 columns]
              precision    recall  f1-score   support

         0.0       1.00      1.00      1.00      9894
         1.0       1.00      1.00      1.00     11409

    accuracy                           1.00     21303
   macro avg       1.00      1.00      1.00     21303
weighted avg       1.00      1.00      1.00     21303


FEATURES:

'FinFlagDist', 'SynFlagDist', 'RstFlagDist', 'PshFlagDist',
       'AckFlagDist', 'DNSoverIP', 'TCPoverIP', 'UDPoverIP', 'MaxLen',
       'MinLen', 'StdDevLen', 'AvgLen', 'MaxIAT', 'MinIAT', 'AvgIAT',
       'AvgWinFlow', 'PktsIOratio', '1stPktLen', 'MaxLenrx', 'MinLenrx',
       'StdDevLenrx', 'AvgLenrx', 'MinIATrx', 'AvgIATrx', 'NumPorts',
       'FlowLEN', 'FlowLENrx', 'repeated_pkts_ratio', 'NumCon', 'NumIPdst',
       'Start_flow', 'DeltaTimeFlow', 'HTTPpkts'

'''