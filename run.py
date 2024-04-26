import pandas as pd
import numpy as np
from dnn_classifier_v2 import DNNClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

data = pd.read_csv("encryption_data_01.csv")
data.head(10)

data_labels = np.array(data['Method'])
data_features = (data.drop(['Plain'], axis=1))
# data_features["Cipher"] = data_features["Cipher"]

# One-hot encode the categorical variables
data_features = pd.get_dummies(data_features)
#Set NAN to 0
data_features = np.nan_to_num(data_features)
data_features = np.array(data_features)

# Encode labels to integers
label_encoder = LabelEncoder()
data_labels_encoded = label_encoder.fit_transform(data_labels)

# Put one quarter of data into testing set
X_train, X_test, y_train, y_test = train_test_split(data_features, data_labels_encoded, test_size=0.25)
print(X_train.shape, X_test.shape)

dnn = DNNClassifier(tensorboard_logdir="./tensorboard_stats", dropout_rate=0.25, learning_rate=0.0005, n_neurons=150, n_hidden_layers=5, random_state=42)
dnn.fit(X_train, y_train, n_epochs=100)

method_predictions= dnn.predict(X_test)
print("Score on test set: {:.2f}%".format(accuracy_score(y_test, method_predictions) * 100))

