from flask import Flask, request, jsonify
import pandas as pd
import joblib

app = Flask(__name__)

print("Step 1: Starting...")

# ----------------------------
# Load Model
# ----------------------------

print("Step 2: Loading Model...")
model = joblib.load("models/sentinel_incident_xgboost.pkl")
print("✓ Model Loaded")

print("Step 3: Loading Severity Encoder...")
severity_encoder = joblib.load("models/severity_encoder.pkl")
print("✓ Severity Encoder Loaded")

print("Step 4: Loading Feature Encoders...")
feature_encoders = joblib.load("models/feature_encoders.pkl")
print("✓ Feature Encoders Loaded")

print("✓ API Ready!")

# ----------------------------
# Home Page
# ----------------------------

@app.route("/")
def home():
    return jsonify({
        "message": "Microsoft Sentinel AI Incident Prioritization API Running"
    })


# ----------------------------
# Prediction API
# ----------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        print("Received JSON:", data)

        df = pd.DataFrame([data])

        # Arrange columns exactly as used during training
        expected_columns = [
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Packet Length Mean",
            "Packet Length Std",
            "Avg Packet Size",
            "Init Fwd Win Bytes",
            "Init Bwd Win Bytes",
            "NetworkRiskScore",
            "TrafficVolume",
            "SessionDuration"
        ]

        df = df[expected_columns]

        # Encode categorical features
        for col in ["TrafficVolume", "SessionDuration"]:
            df[col] = feature_encoders[col].transform(df[col])

        # Prediction
        prediction = int(model.predict(df)[0])
        probability = model.predict_proba(df)[0]

        severity = str(severity_encoder.inverse_transform([prediction])[0])

        confidence = float(round(float(max(probability)) * 100, 2))
        risk_score = int(confidence)

        # Priority
        if severity == "High":
            priority = "P1"
            action = "Immediate Investigation Required"
        elif severity == "Medium":
            priority = "P2"
            action = "Review Incident"
        else:
            priority = "P3"
            action = "Monitor"

        top_features = [
            "Flow Duration",
            "Flow Bytes/s",
            "Packet Length Mean",
            "Avg Packet Size",
            "NetworkRiskScore"
        ]

        return jsonify({
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "priority": priority,
            "recommended_action": action,
            "top_features": top_features
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
    # ----------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)