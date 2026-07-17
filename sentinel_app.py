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

        # Create a row with default value 0 for every feature
        row = {}
        for col in expected_columns:
            row[col] = data.get(col, 0)

        df = pd.DataFrame([row])

        # Convert everything to numeric
        for col in expected_columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        prediction = int(model.predict(df)[0])
        probability = model.predict_proba(df)[0]

        severity = severity_encoder.inverse_transform([prediction])[0]

        confidence = round(float(max(probability)) * 100, 2)
        risk_score = int(confidence)

        if severity == "High":
            priority = "P1"
            action = "Immediate Investigation Required"
        elif severity == "Medium":
            priority = "P2"
            action = "Review Incident"
        else:
            priority = "P3"
            action = "Monitor"

        return jsonify({
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "priority": priority,
            "recommended_action": action,
            "top_features": [
                "Flow Duration",
                "Flow Bytes/s",
                "Packet Length Mean",
                "Avg Packet Size",
                "NetworkRiskScore"
            ]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    # ----------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
