import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, MinMaxScaler
from imblearn.over_sampling import SMOTE
import joblib


# Load dataset
def load_data(file_path):
    """
    Load the CSV dataset containing packet information.
    The dataset must have a 'label' column indicating if a packet is malicious or not.
    """
    try:
        data = pd.read_csv(file_path)
        print("Data loaded successfully!")
        return data
    except FileNotFoundError:
        print(f"File not found at {file_path}")
        return None


# Preprocess dataset
def preprocess_data(data):
    """
    Preprocess the data by encoding non-numeric columns, balancing the dataset, and splitting features and labels.
    """
    # Separate features and label
    X = data.drop(columns=['label'])
    y = data['label']

    # Drop IP addresses (non-predictive)
    X = X.drop(columns=['source_ip', 'dest_ip'])

    # Encode categorical features
    if 'protocol' in X.columns:
        protocol_encoder = OneHotEncoder(sparse=False)
        protocol_encoded = protocol_encoder.fit_transform(X[['protocol']])
        protocol_cols = protocol_encoder.get_feature_names_out(['protocol'])
        protocol_df = pd.DataFrame(protocol_encoded, columns=protocol_cols, index=X.index)
        X = pd.concat([X, protocol_df], axis=1).drop(columns=['protocol'])

    if 'flags' in X.columns:
        X['flags'] = LabelEncoder().fit_transform(X['flags'].fillna('None'))

    # Normalize numeric features
    scaler = MinMaxScaler()
    X[['size']] = scaler.fit_transform(X[['size']])

    # Convert labels to numeric
    y = LabelEncoder().fit_transform(y)

    # Balance dataset using SMOTE
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    # Split into training and testing data
    X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)
    return X_train, X_test, y_train, y_test


# Train Random Forest model with hyperparameter tuning
def train_model(X_train, y_train):
    """
    Train a Random Forest Classifier with optimal hyperparameters.
    """
    # Define hyperparameter grid
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, 30, None],
        'min_samples_split': [2, 5, 10, 20],
        'min_samples_leaf': [1, 2, 4, 10],
        'max_features': ['auto', 'sqrt', 'log2']
    }

    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=42),
        param_grid,
        cv=3,
        scoring='accuracy',
        n_jobs=-1
    )
    grid_search.fit(X_train, y_train)
    print(f"Best parameters: {grid_search.best_params_}")

    # Train model with best parameters
    model = grid_search.best_estimator_
    print("Model training complete.")
    return model


# Evaluate model
def evaluate_model(model, X_test, y_test):
    """
    Evaluate the model on the test data and print the results.
    """
    y_pred = model.predict(X_test)
    print("Model Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))


# Save model
def save_model(model, file_name):
    """
    Save the trained model to a file.
    """
    joblib.dump(model, file_name)
    print(f"Model saved to {file_name}.")


# Main function
def main():
    file_path = "./network_packets.csv"
    data = load_data(file_path)

    if data is not None:
        X_train, X_test, y_train, y_test = preprocess_data(data)
        model = train_model(X_train, y_train)
        evaluate_model(model, X_test, y_test)

        save_model_path = "optimized_random_forest_packet_classifier.pkl"
        save_model(model, save_model_path)


# Run the program
if __name__ == "__main__":
    main()
