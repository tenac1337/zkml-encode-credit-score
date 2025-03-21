import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
import tqdm
import os
import json
import ezkl
import asyncio  # Added missing asyncio import

# Set Rust logging level for EZKL debugging
os.environ["RUST_LOG"] = "trace"

# Set global numerical precision for consistency
np.set_printoptions(precision=10)
np.random.seed(42)

# Function to load and preprocess data
def load_and_preprocess_data(file_path):
    df = pd.read_csv(file_path)
    label_encoders = {}
    ordinal_cols = ["Education", "Credit Score"]
    
    for col in ordinal_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le

    df = pd.get_dummies(df, columns=["Gender", "Marital Status", "Home Ownership"], drop_first=True)
    df = df.astype({col: int for col in df.select_dtypes(include=['bool']).columns})
    
    scaler = StandardScaler()
    df[["Age", "Income", "Number of Children"]] = scaler.fit_transform(df[["Age", "Income", "Number of Children"]])
    
    df = df.apply(pd.to_numeric, errors="coerce")
    X = df.drop(columns=["Credit Score"])
    y = df["Credit Score"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    return X_train, X_test, y_train, y_test, label_encoders, scaler, df

# Define the model class
class Model(nn.Module):
    def __init__(self, input_size):
        super(Model, self).__init__()
        self.fc1 = nn.Linear(input_size, 20)
        self.fc2 = nn.Linear(20, 20)
        self.fc3 = nn.Linear(20, 3)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        x = self.relu(x)
        x = self.fc3(x)
        return x

# Function to train the model
def train_model(model, train_X, train_y, epochs=800, lr=0.01):
    loss_fn = nn.CrossEntropyLoss()
    optimizer = torch.optim.SGD(model.parameters(), lr=lr)
    loss_list, accuracy_list = np.zeros((epochs,)), np.zeros((epochs,))
    
    for epoch in tqdm.trange(epochs):
        predicted_y = model(train_X)
        loss = loss_fn(predicted_y, train_y)
        loss_list[epoch] = loss.item()
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    
    return loss_list, accuracy_list

# Function for predictions
def predictions(model, test_X, test_y, df, scaler, label_encoders):
    print("\n🔍 Evaluating Model on Test Data...")
    model.eval()
    test_X = test_X.to(model.fc1.weight.device)
    test_y = test_y.to(model.fc1.weight.device)
    
    with torch.no_grad():
        y_pred_logits = model(test_X)
        y_pred = torch.argmax(y_pred_logits, dim=1)
    
    y_pred_np = y_pred.cpu().numpy()
    test_y_np = test_y.cpu().numpy()
    test_X_np = test_X.cpu().numpy()
    
    original_features = scaler.inverse_transform(test_X_np[:, :3])
    credit_score_labels = {v: k for v, k in enumerate(label_encoders["Credit Score"].classes_)}
    
    results_df = pd.DataFrame(original_features, columns=["Age", "Income", "Number of Children"])
    original_categorical = pd.DataFrame(test_X_np[:, 3:], columns=[col for col in df.columns if col not in ["Age", "Income", "Number of Children", "Credit Score"]])
    
    results_df = pd.concat([results_df, original_categorical], axis=1)
    results_df["Predicted Credit Score"] = [credit_score_labels[val] for val in y_pred_np]
    results_df["Actual Credit Score"] = [credit_score_labels[val] for val in test_y_np]
    
    print("\n🔹 Sample of Real-World Predictions:")
    print(results_df.head(10))
    return results_df


# Function to evaluate the model
def evaluate_model(model, test_X, test_y):
    model.eval()
    with torch.no_grad():
        y_pred_logits = model(test_X)
        y_pred = torch.argmax(y_pred_logits, dim=1)
    
    test_acc = accuracy_score(test_y.cpu().numpy(), y_pred.cpu().numpy())
    test_precision = precision_score(test_y.cpu().numpy(), y_pred.cpu().numpy(), average='weighted')
    test_recall = recall_score(test_y.cpu().numpy(), y_pred.cpu().numpy(), average='weighted')
    
    print(f"Test Accuracy: {test_acc:.4f}")
    print(f"Precision: {test_precision:.4f}")
    print(f"Recall: {test_recall:.4f}")

# Function to convert and export model to ONNX
def export_model_to_onnx(model, test_X, model_path='network.onnx'):
    x = test_X[0].reshape(1, test_X.shape[1])
    model.eval()
    torch.onnx.export(model, x, model_path, export_params=True, opset_version=10, 
                      do_constant_folding=True, input_names=['input'], output_names=['output'], 
                      dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}})
    print("Model exported to ONNX.")
    data_array = ((x).detach().numpy()).reshape([-1]).tolist()
    data = dict(input_data=[data_array])
    json.dump(data, open('input.json', 'w'))

# Function to generate and verify proof using ezkl
async def generate_and_verify_proof():
    model_path = 'network.onnx'
    data_path = 'input.json'
    witness_path = 'witness.json'
    proof_path = 'proof.json'
    calibration_path = "calibration.json"

    res = ezkl.gen_settings()
    assert res is True


    res = await ezkl.calibrate_settings(target="resources", max_logrows=12, scales=[2, 3, 5])
    assert res is True
    # Ensure Calibration JSON Exists
    # if not os.path.exists(calibration_path):
    #     print("🔄 Recreating calibration.json...")
    #     res = await ezkl.calibrate_settings(target="resources", max_logrows=12, scales=[2, 3, 5])
    #     assert res is True
    # else:
    #     print("✅ Using existing calibration.json")

    res = ezkl.compile_circuit()
    assert res is True

    res = await ezkl.get_srs()
    assert res is True

    res = ezkl.setup()
    assert res is True

    res = await ezkl.gen_witness()
    assert os.path.isfile(witness_path)

    proof = ezkl.prove(proof_type="single", proof_path=proof_path)
    assert os.path.isfile(proof_path)

    res = ezkl.verify()
    assert res is True
    print("✅ Proof verified successfully.")


# Main execution function
def main():
    file_path = "/home/rchak007/github/ZKML/creditLoan/CreditScoreClassificationDataset.csv"
    train_X, test_X, train_y, test_y, label_encoders, scaler, df = load_and_preprocess_data(file_path)
    
    train_X = torch.tensor(train_X.to_numpy(), dtype=torch.float32)
    test_X = torch.tensor(test_X.to_numpy(), dtype=torch.float32)
    train_y = torch.tensor(train_y.to_numpy(), dtype=torch.long)
    test_y = torch.tensor(test_y.to_numpy(), dtype=torch.long)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = Model(train_X.shape[1]).to(device)
    train_X, test_X, train_y, test_y = train_X.to(device), test_X.to(device), train_y.to(device), test_y.to(device)
    
    print("Training model...")
    train_model(model, train_X, train_y)
    
    print("Evaluating model...")
    evaluate_model(model, test_X, test_y)

    print("Making predictions...")
    results_df = predictions(model, test_X, test_y, df, scaler, label_encoders)
        
    
    print("Exporting model to ONNX...")
    export_model_to_onnx(model, test_X)
    
    # print("Generating and verifying proof...")
    # generate_and_verify_proof()
    print("Generating and verifying proof...")
    asyncio.run(generate_and_verify_proof())  # <-- Use asyncio to run the async function
    
    
if __name__ == "__main__":
    main()

