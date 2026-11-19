import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# 1. Load your dataset
df = pd.read_csv(r'C:\Users\tejas\OneDrive\Desktop\VAbox\vabox_dataset.csv')

X = df.drop(columns=['sample_id', 'label', 'subclass'])
y_raw = df['subclass']

encoder = LabelEncoder()
y = encoder.fit_transform(y_raw)

# Split data for training the ML fallback model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
xgb_clf = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42, eval_metric='mlogloss')
xgb_clf.fit(X_train, y_train)

# ==========================================
# TIER 1: DETERMINISTIC RULE-BASED ENGINE
# ==========================================
def rule_based_detect(sample_row):
    """
    Fast, explicit checks using known kernel telemetry markers.
    Returns the classification instantly if a definitive rule triggers.
    """
    if sample_row['bpf_indicator'] == 1:
        return "EBPF (Detected via BPF trace signature)"
    
    if sample_row['hidden_module_anomaly'] == 1:
        return "LKM (Detected via hidden module anomaly)"
        
    # If no hard rule triggers, return None to escalate to Tier 2 (ML)
    return None

# ==========================================
# TIER 2: ML CLASSIFIER FALLBACK ENGINE
# ==========================================
def ml_fallback_detect(sample_row):
    """
    Uses the XGBoost model to classify subtle or ambiguous telemetry behavior.
    """
    # Reshape row for model prediction
    features_df = pd.DataFrame([sample_row]).drop(columns=['sample_id', 'label', 'subclass'], errors='ignore')
    pred_encoded = xgb_clf.predict(features_df)[0]
    predicted_label = encoder.inverse_transform([pred_encoded])[0]
    return f"{predicted_label} (Classified via ML Anomaly Scoring)"

# ==========================================
# HYBRID DETECTION PIPELINE IN ACTION
# ==========================================
def analyze_sample(sample_row):
    # Step 1: Run Tier 1 Rules
    verdict = rule_based_detect(sample_row)
    
    if verdict is not None:
        return f"[Tier 1 Rule Match] -> {verdict}"
    else:
        # Step 2: Fall back to Tier 2 ML if rules are inconclusive
        return f"[Tier 2 ML Fallback] -> {ml_fallback_detect(sample_row)}"

# Test the pipeline across your dataset rows
print("Running Hybrid Detection Pipeline on Dataset Samples:\n" + "="*55)
for idx, row in df.head(10).iterrows():
    result = analyze_sample(row)
    print(f"Sample {row['sample_id']}: {result}")