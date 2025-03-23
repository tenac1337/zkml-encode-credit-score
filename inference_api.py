from fastapi import FastAPI
from pydantic import BaseModel
import torch
import pandas as pd
import numpy as np
import joblib
import json
import ezkl
import asyncio
from model_def import Model  # Make sure to include your model class here
import os


app = FastAPI()

# Load saved model + preprocessors
model = Model(input_size=7)  # replace 7 with your actual input size
model.load_state_dict(torch.load("model.pth"))
model.eval()

scaler = joblib.load("scaler.joblib")
label_encoders = joblib.load("label_encoders.joblib")

class UserData(BaseModel):
    age: float
    income: float
    children: int
    education: str
    gender: str
    marital_status: str
    home_ownership: str

# Step 1: Preprocess input
def preprocess_user_input(data: UserData):
    # input_dict = data.dict()
    input_dict = data.model_dump()

    df = pd.DataFrame([input_dict])

    # Encode education
    df["Education"] = label_encoders["Education"].transform(df["education"])
    df.drop("education", axis=1, inplace=True)

    # Encode one-hot categorical variables manually
    df["Gender_Male"] = 1 if df["gender"].iloc[0].lower() == "male" else 0
    df["Marital Status_Single"] = 1 if df["marital_status"].iloc[0].lower() == "single" else 0
    df["Home Ownership_Rent"] = 1 if df["home_ownership"].iloc[0].lower() == "rent" else 0
    df.drop(["gender", "marital_status", "home_ownership"], axis=1, inplace=True)


    # Rename to match original training column names
    df.rename(columns={
        "age": "Age",
        "income": "Income",
        "children": "Number of Children"
    }, inplace=True)


    # Reorder if necessary and scale
    df_scaled = df.copy()
    # df_scaled[["age", "income", "children"]] = scaler.transform(df[["age", "income", "children"]])
    
    df_scaled[["Age", "Income", "Number of Children"]] = scaler.transform(
        df[["Age", "Income", "Number of Children"]]
    )
    return torch.tensor(df_scaled.to_numpy(), dtype=torch.float32)

# Step 2: Export model to ONNX and write input.json
def export_input_for_ezkl(model, input_tensor, model_path='network.onnx', input_path='input.json'):
    x = input_tensor.reshape(1, -1)
    torch.onnx.export(
        model, x, model_path, export_params=True, opset_version=10,
        do_constant_folding=True, input_names=['input'], output_names=['output'],
        dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}}
    )
    data_array = x.detach().numpy().reshape([-1]).tolist()
    data = dict(input_data=[data_array])
    json.dump(data, open(input_path, 'w'))

# Step 3: Run EZKL proof and return result
async def run_ezkl_pipeline():
    calibration_path = "calibration.json"
    if not os.path.exists(calibration_path):
        print("Generating calibration.json...")
        res = await ezkl.calibrate_settings(target="resources", max_logrows=12, scales=[2, 3, 5])
        assert res is True
    else:
        print("Using existing calibration.json")

    assert ezkl.gen_settings()
    assert ezkl.compile_circuit()
    assert await ezkl.get_srs()
    assert ezkl.setup()
    assert await ezkl.gen_witness()
    proof = ezkl.prove(proof_type="single", proof_path="proof.json")
    assert ezkl.verify()

    with open("proof.json") as f:
        return json.load(f)

# Step 4: The API endpoint
@app.post("/generate-proof")
async def generate_proof(data: UserData):
    input_tensor = preprocess_user_input(data)               # Step 1
    export_input_for_ezkl(model, input_tensor)               # Step 2
    proof = await run_ezkl_pipeline()                        # Step 3
    return {"status": "✅ proof generated", "proof": proof}
