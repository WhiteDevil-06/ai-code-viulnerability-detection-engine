import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from training.train_models import evaluate_candidate, find_optimal_threshold


from sklearn.preprocessing import StandardScaler


def test_evaluate_candidate() -> None:
    train_df = pd.DataFrame({
        "cleaned_code": ["def safe_one(): pass", "def vuln_one(): eval(x)"],
        "label": [0, 1],
        "nloc": [1.0, 2.0],
        "complexity": [1.0, 2.0],
        "token_count": [4.0, 8.0],
        "top_nesting_level": [0.0, 0.0]
    })
    val_df = pd.DataFrame({
        "cleaned_code": ["def safe_two(): pass", "def vuln_two(): eval(y)"],
        "label": [0, 1],
        "nloc": [1.0, 2.0],
        "complexity": [1.0, 2.0],
        "token_count": [4.0, 8.0],
        "top_nesting_level": [0.0, 0.0]
    })

    vectorizer = TfidfVectorizer(analyzer="word")
    scaler = StandardScaler()
    model = LogisticRegression()

    f1, prec, rec, probs, trained_model = evaluate_candidate(
        vectorizer, scaler, model, train_df, val_df
    )

    assert isinstance(f1, float)
    assert isinstance(prec, float)
    assert isinstance(rec, float)
    assert len(probs) == 2
    assert trained_model is model


def test_find_optimal_threshold() -> None:
    y_val = pd.Series([0, 0, 1, 1])
    probs = np.array([0.1, 0.2, 0.8, 0.9])

    best_threshold, best_f1, _ = find_optimal_threshold(y_val, probs)

    assert 0.2 < best_threshold <= 0.8
    assert best_f1 == 1.0
