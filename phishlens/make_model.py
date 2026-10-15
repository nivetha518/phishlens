import joblib
model_data = {
    "features": ["length", "dots", "hyphens", "at", "https", "ip", "entropy"],
    "coef": [0.5, 1.2, 1.5, 2.0, -1.0, 2.5, 0.3]
}
joblib.dump(model_data, "model.joblib")
print("model.joblib created!")