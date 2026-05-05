lhjojlhjhnmhmprint('walo')print('walo')print('walo')print('walo')# log_sentinel.py

from sklearn.ensemble import IsolationForest
import numpy as np

# =========================
# 1. Feature Extraction
# =========================
def extract_features(logs):
    features = []
    for log in logs:
        log_lower = log.lower()

        features.append([
            len(log),  # tille ligne
            int("error" in log_lower),
            int("failed" in log_lower),
            int("unauthorized" in log_lower),
            int("login" in log_lower),
            int("attack" in log_lower)
        ])
    
    return np.array(features)


# =========================
# 2. Model Initialization
# =========================
model = IsolationForest(contamination=0.1, random_state=42)


def train_model(logs):
    X = extract_features(logs)
    model.fit(X)


# =========================
# 3. Prediction
# =========================
def analyze_logs(logs):
    X = extract_features(logs)
    
    preds = model.predict(X)  # 1 normal / -1 anomaly
    scores = model.decision_function(X)  # score
    
    results = []
    for i in range(len(logs)):
        results.append({
            "log": logs[i],
            "prediction": "anomaly" if preds[i] == -1 else "normal",
            "score": float(scores[i])
        })
        
    
    return results

if __name__ == "__main__":
    test_logs = [
        "User login successful",
        "Error: database failed",
        "Unauthorized access attempt",
        "Normal request  attack received",
        "Multiple failed login attempts detected",
        "System running smoothly"
    ]

    # train
    train_model(test_logs)

    # analyze
    results = analyze_logs(test_logs)

    # print results
    for r in results:
        print(f"[{r['prediction'].upper()}] {r['log']} (score: {r['score']:.3f})")