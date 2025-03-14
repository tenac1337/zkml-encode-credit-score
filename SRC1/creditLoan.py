import pandas as pd
import numpy as np
import os
import joblib  # For saving the trained model
import onnx
import onnxruntime as ort
import torch
import torch.nn as nn
import torch.onnx
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier  # Simple classifier for first iteration

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

import json
import ezkl
print(ezkl.__version__)

import asyncio


# Define paths
ROOT_DIR = "/home/rchak007/github/ZKML/creditLoan"
DATA_PATH = os.path.join(ROOT_DIR, "data", "Credit Score Classification Dataset.csv")
ONNX_MODEL_PATH = os.path.join(ROOT_DIR, "credit_model.onnx")
PICKLE_MODEL_PATH = os.path.join(ROOT_DIR, "credit_model.pkl")
COMPILED_MODEL_PATH = os.path.join(ROOT_DIR, "credit_model.compiled")
SETTINGS_PATH = os.path.join(ROOT_DIR, "settings.json")
CALIBRATION_PATH = os.path.join(ROOT_DIR, "calibration.json")
WITNESS_PATH = os.path.join(ROOT_DIR, "witness.json")
PROOF_PATH = os.path.join(ROOT_DIR, "test.pf")
VK_PATH = os.path.join(ROOT_DIR, "test.vk")
PK_PATH = os.path.join(ROOT_DIR, "test.pk")
RESOURCES_DIR = os.path.join(ROOT_DIR, "resources")
INPUT_JSON_PATH = os.path.join(ROOT_DIR, "input.json")
# DATA_PATH = os.path.join(ROOT_DIR, "input.json")

# Ensure resources directory exists
os.makedirs(RESOURCES_DIR, exist_ok=True)


# 🔹 Define MLP Model (Global Scope)
class CreditScoreNN(nn.Module):
    def __init__(self, input_dim):
        super(CreditScoreNN, self).__init__()
        self.fc1 = nn.Linear(input_dim, 64)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(64, 3)  # 3 output classes (High, Average, Low)

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x

### 1️⃣ Load Dataset ###
def load_dataset():
    """Loads the credit score dataset and returns a Pandas DataFrame."""
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    print("🔹 Columns in the dataset:", df.columns.tolist())  # ✅ Debug step
    df.dropna(inplace=True)  # Drop missing values
    return df

### 2️⃣ Preprocess Dataset ###
def preprocess_data(df):
    """Encodes categorical variables correctly and ensures numeric data."""
    
    print("Preprocessing dataset...")

    # **Label Encoding for Ordinal Features**
    label_encoders = {}
    ordinal_cols = ["Education", "Credit Score"]
    
    for col in ordinal_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le  

    # **One-Hot Encoding for Non-Ordinal Features**
    df = pd.get_dummies(df, columns=["Gender", "Marital Status", "Home Ownership"], drop_first=True)

    # 🚨 Fix: Convert all `bool` columns to `int`
    df = df.astype({col: int for col in df.select_dtypes(include=['bool']).columns})

    # **Normalize numerical features**
    scaler = StandardScaler()
    df[["Age", "Income", "Number of Children"]] = scaler.fit_transform(df[["Age", "Income", "Number of Children"]])

    # **Convert everything to numeric to avoid errors**
    df = df.apply(pd.to_numeric, errors="coerce")

    # **Final Debug Check**
    print("✅ Final column data types after encoding:")
    print(df.dtypes)

    # **Split features and target**
    X = df.drop(columns=["Credit Score"])
    y = df["Credit Score"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    return X_train, X_test, y_train, y_test, label_encoders, scaler




### 3️⃣ Train Model ###
##                                          Random Forest will not work with EZKL   ***********************  
def train_model(X_train, y_train):
    """Trains a Random Forest classifier and saves the model."""
    print("Training model...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    joblib.dump(clf, PICKLE_MODEL_PATH)  # Save the trained model
    print(f"Model saved at {PICKLE_MODEL_PATH}")
    
    return clf


def train_mlp(X_train, y_train, num_epochs=50, batch_size=16, learning_rate=0.01):
    """
    Trains a simple MLP model on the credit score dataset.
    """
    print("🔹 Training MLP Model...")

    # Convert data to PyTorch tensors
    X_train_tensor = torch.tensor(X_train.values, dtype=torch.float32)
    y_train_tensor = torch.tensor(y_train.values, dtype=torch.long)  # Classification requires LongTensor

    # Create DataLoader
    dataset = TensorDataset(X_train_tensor, y_train_tensor)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    # Initialize model, loss function, and optimizer
    input_dim = X_train.shape[1]
    model = CreditScoreNN(input_dim)
    criterion = nn.CrossEntropyLoss()  # For multi-class classification
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    # Training loop
    for epoch in range(num_epochs):
        total_loss = 0
        for batch_X, batch_y in dataloader:
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{num_epochs}], Loss: {total_loss:.4f}")

    print("✅ Training complete!")
    return model

### 4️⃣ Convert Model to ONNX ###
def convert_to_onnx(mlp_model, X_train, random_input) :
    """Converts the trained MLP model to ONNX format for EZKL."""
    print("🔹 Converting trained MLP model to ONNX...")

    # dummy_input = torch.tensor(X_train.iloc[:1].values, dtype=torch.float32)

    # ✅ Convert NumPy array to PyTorch tensor
    torch_input = torch.tensor(random_input, dtype=torch.float32)

    # Ensure the trained model is in evaluation mode
    mlp_model.eval()

    # Export to ONNX
    torch.onnx.export(
        mlp_model, torch_input, ONNX_MODEL_PATH,
        input_names=["input"], output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
        opset_version=10
    )
    # ✅ Dump input data to JSON for EZKL
    data_array = ((torch_input).detach().numpy()).reshape([-1]).tolist()
    data = dict(input_data=[data_array])
    json.dump(data, open(INPUT_JSON_PATH, 'w'))
    print(f"✅ Input data saved for EZKL at {INPUT_JSON_PATH}")
    print(f"✅ Model successfully converted to ONNX and saved at {ONNX_MODEL_PATH}")


### 5️⃣ Verify ONNX Model Works ###
def verify_onnx(real_input):
    """Runs ONNX inference using a real sample input instead of random data."""
    print("🔹 Running ONNX inference on real input...")

    # Load ONNX model
    ort_session = ort.InferenceSession(ONNX_MODEL_PATH)

    # ✅ Ensure the input is in correct format
    input_data = np.array(real_input).reshape(1, -1).astype(np.float32)

    # Run inference on the ONNX model
    onnx_pred = ort_session.run(None, {"input": input_data})[0]

    print(f"✅ ONNX Inference Completed. Output (logits): {onnx_pred}")

    return onnx_pred


def decode_onnx_output(onnx_pred):
    """Converts ONNX model output (logits) into real-world labels."""
    class_labels = ["Low", "Average", "High"]  # Adjust based on your dataset

    # Get the index of the highest value (predicted class)
    predicted_class = np.argmax(onnx_pred)

    return class_labels[predicted_class]


import json
import ezkl

async def calibrate_model(X_train):
    """Calibrates the ONNX model for Zero-Knowledge execution using EZKL."""
    print("🔹 Calibrating model for EZKL...")

    cal_path = "calibration.json"

    # ✅ Debug: Print file paths before running EZKL
    print("\n📂 Debugging File Paths:")
    print(f" - Current Directory: {os.getcwd()}")
    print(f" - ONNX Model Path: {os.path.abspath(ONNX_MODEL_PATH)}")
    print(f" - Calibration File: {os.path.abspath(cal_path)}")
    print(f" - Resources Directory: {os.path.abspath('resources')}")
    print(f" - Contents of Current Directory: {os.listdir(os.getcwd())}")
    print(f" - Contents of Resources Directory: {os.listdir('resources')}") 

    # ✅ Ensure ONNX model exists before calibration
    if not os.path.exists(ONNX_MODEL_PATH):
        raise FileNotFoundError(f"❌ ERROR: ONNX model not found at {ONNX_MODEL_PATH}. Ensure it was generated before calibration.")

    # ✅ Create a calibration input using the same shape as X_train
    data_array = (torch.rand(20, X_train.shape[1], requires_grad=True).detach().numpy()).reshape([-1]).tolist()
    data = dict(input_data=[data_array])

    # Save calibration input to a file
    json.dump(data, open(cal_path, 'w'))

    # Run EZKL calibration
    # ✅ Force proper async execution
    await ezkl.calibrate_settings(cal_path, "credit_model.onnx", "settings.json", "resources")

    print("✅ Calibration complete! Settings saved in 'settings.json'.")    


async def run_ezkl(X_test):

    py_run_args = ezkl.PyRunArgs()
    py_run_args.input_visibility = "private"
    py_run_args.output_visibility = "public"
    py_run_args.param_visibility = "fixed"

    print("🔹 Generating EZKL settings...") 
    ezkl.gen_settings(ONNX_MODEL_PATH, SETTINGS_PATH)
    # await ezkl.calibrate_settings(CALIBRATION_PATH, ONNX_MODEL_PATH, SETTINGS_PATH, RESOURCES_DIR)    

    print("🔹 Calibrating model for EZKL...")
    print(" CALIBRATION_PATH = ", CALIBRATION_PATH)
    print(" ONNX_MODEL_PATH = ", ONNX_MODEL_PATH)
    print(" SETTINGS_PATH = ", SETTINGS_PATH)
    print(" RESOURCES_DIR = ", RESOURCES_DIR)

    print("🔹 Generating Calibration Data from Test Set...")
    # cal_data = dict(input_data=X_test.iloc[:20].values.flatten().tolist())
    # cal_data = dict(input_data=X_test.values.flatten().tolist())  # ✅ Uses full dataset
    # ✅ Generate correctly formatted calibration data
    cal_path = generate_calibration_json(X_test)    

    # # ✅ Save the calibration data dynamically
    # with open(CALIBRATION_PATH, 'w') as f:
    #     json.dump(cal_data, f, indent=4)

    await ezkl.calibrate_settings(
        data=cal_path, 
        # data=INPUT_JSON_PATH,
        model=ONNX_MODEL_PATH, 
        settings=SETTINGS_PATH, 
        #target=RESOURCES_DIR 
        target="resources",
        max_logrows=12,   # ✅ Match reference program
        scales=[2]        # ✅ Match reference program        
        
    )

    print("🔹 Compiling circuit...")
    res = ezkl.compile_circuit(ONNX_MODEL_PATH, COMPILED_MODEL_PATH, SETTINGS_PATH)
    assert res == True
    print("🔹 Get SRS...")
    await ezkl.get_srs(SETTINGS_PATH)

    print("🔹 Setup...")
    res = ezkl.setup(model=COMPILED_MODEL_PATH, vk_path=VK_PATH, pk_path=PK_PATH,srs_path=None, witness_path=None)
    assert res == True

    print("🔹 generate witness...")
    # await ezkl.gen_witness(WITNESS_PATH, COMPILED_MODEL_PATH, WITNESS_PATH)
    await ezkl.gen_witness(INPUT_JSON_PATH, COMPILED_MODEL_PATH, WITNESS_PATH)

    

    print(" WITNESS_PATH = ", WITNESS_PATH)
    print(" COMPILED_MODEL_PATH = ", COMPILED_MODEL_PATH)
    print(" PK_PATH = ", PK_PATH)
    print(" PROOF_PATH = ", PROOF_PATH)
    print("🔹 Checking all files before proof generation...")
    print(f"  - Witness Path Exists? {os.path.exists(WITNESS_PATH)}")
    print(f"  - Compiled Model Path Exists? {os.path.exists(COMPILED_MODEL_PATH)}")
    print(f"  - Proving Key Path Exists? {os.path.exists(PK_PATH)}")
    print(f"  - Proof Path Exists (Before Running)? {os.path.exists(PROOF_PATH)}")

    print("🔹 PROVE...")
    res = ezkl.prove(witness=WITNESS_PATH, model=COMPILED_MODEL_PATH, pk_path=PK_PATH, proof_path=PROOF_PATH, proof_type="single", srs_path=None)
    assert res == True
    print("🔹 get Verify...")
    res = ezkl.verify(PROOF_PATH, SETTINGS_PATH, VK_PATH)
    assert res == True
    print("✅ Proof Verified Successfully!")

def generate_random_input(X_test):
    """Generates a properly formatted random input for ONNX and EZKL."""
    print("🔹 Generating Random Input for Proof...")

    # ✅ Pick the first sample from test data
    random_input = X_test.iloc[0].values.reshape(1, -1).astype(np.float32)

    print("✅ Random Input Generated:", random_input)
    
    return random_input

def generate_calibration_json(X_test):
    """Generates properly formatted calibration.json for EZKL."""
    print("🔹 Generating Calibration Data from Test Set...")

    # ✅ Ensure no NaN values
    X_test_cleaned = X_test.fillna(0).values.flatten().tolist()

    cal_data = {"input_data": [X_test_cleaned]}  # ✅ Correct JSON structure

    # ✅ Save to file
    with open(CALIBRATION_PATH, 'w') as f:
        json.dump(cal_data, f, indent=4)

    print(f"✅ Calibration data saved at {CALIBRATION_PATH}")

    return CALIBRATION_PATH



### 🔥 Main Execution ###
def main():
    df = load_dataset()
    print(df.head())

    X_train, X_test, y_train, y_test, label_encoders, scaler = preprocess_data(df)
   
    mlp_model = train_mlp(X_train, y_train)
    #  *********************** not using random Forest as it does not with EZKL
    #  clf = train_model(X_train, y_train)
    

    random_input = generate_random_input(X_test)  # Get a properly formatted test input
    convert_to_onnx(mlp_model, X_train, random_input)

    # real_input = X_test.iloc[0].values  # Take first sample for testing
    # # ✅ Get the original values before encoding/scaling
    # original_sample = df.iloc[X_test.index[0]]  # Get the same row from the original dataset

    # print("\n🔹 Real Input (Original Values Before Preprocessing):")
    # print(original_sample)

    onnx_output = verify_onnx(random_input)

    print("✅ Script completed successfully!")

    # ✅ Decode ONNX output into real-world credit score label
    predicted_label = decode_onnx_output(onnx_output)
    print(f"🔹 Predicted Credit Score: {predicted_label}")


    # ✅ Pass X_train for calibration
    # asyncio.run(calibrate_model(X_train))   --- OLD.. 

    asyncio.run(run_ezkl(X_test))
    print("✅ ZKML Pipeline Successfully Completed!")    

    print("✅ ZKML Pipeline Successfully Completed!")


if __name__ == "__main__":
    main()

