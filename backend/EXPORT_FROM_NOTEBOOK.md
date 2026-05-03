# Export model artifacts from notebook

Run the following cell at the end of your notebook after training `xgb_clf` and creating `X_train` and `scaler`:

```python
import json
import joblib
from pathlib import Path

out_dir = Path("backend/model")
out_dir.mkdir(parents=True, exist_ok=True)

xgb_clf.save_model(out_dir / "best_xgboost_model.json")
joblib.dump(scaler, out_dir / "robust_scaler.joblib")

with open(out_dir / "feature_columns.json", "w", encoding="utf-8") as f:
    json.dump(X_train.columns.tolist(), f, ensure_ascii=False, indent=2)

print("Artifacts exported to:", out_dir.resolve())
```

Then start API:

```bash
pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --port 8000
```

