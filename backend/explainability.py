"""
explainability.py
-------------------
Adds explainability to the URL phishing Random Forest model using SHAP
(SHapley Additive exPlanations) — a well-established, widely used technique
for explaining individual predictions from tree-based ML models like
Random Forest.

Instead of just saying "84% phishing probability", this lets the dashboard
show WHICH of the 25 URL features pushed the prediction toward phishing
vs safe, and by how much.

This module is defensive about SHAP's output shape, since it has changed
across versions (older shap returns a list of arrays, one per class;
newer shap returns a single 3D array of shape (samples, features, classes)).
Both are handled here.
"""

import shap
import numpy as np


def get_feature_explanation(model, features_df, top_n=5):
    """
    Given a trained RandomForestClassifier and a single-row DataFrame of
    features (same columns the model was trained on), return the top_n
    features that most influenced the PHISHING (positive class) prediction,
    ranked by absolute SHAP value (impact on the prediction).

    Returns a list of dicts:
        [{'feature': 'has_https', 'value': 0, 'impact': 0.18, 'direction': 'increases_risk'}, ...]
    sorted by impact (largest first).
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(features_df)

    feature_names = list(features_df.columns)
    feature_values = features_df.iloc[0].to_dict()

    # Handle both possible SHAP output shapes:
    # - list of arrays (older shap): shap_values[1] = (n_samples, n_features) for class 1
    # - single 3D array (newer shap): shap_values[sample_idx, :, class_idx]
    if isinstance(shap_values, list):
        # list of per-class arrays; class index 1 = phishing/positive class
        class_idx = 1 if len(shap_values) > 1 else 0
        row_shap = shap_values[class_idx][0]
    else:
        arr = np.array(shap_values)
        if arr.ndim == 3:
            # shape (n_samples, n_features, n_classes)
            class_idx = 1 if arr.shape[2] > 1 else 0
            row_shap = arr[0, :, class_idx]
        elif arr.ndim == 2:
            # shape (n_samples, n_features) - binary case, single output
            row_shap = arr[0]
        else:
            row_shap = arr.flatten()

    explanations = []
    for fname, shap_val in zip(feature_names, row_shap):
        explanations.append({
            'feature': fname,
            'value': feature_values.get(fname),
            'impact': round(float(abs(shap_val)), 4),
            'raw_impact': round(float(shap_val), 4),
            'direction': 'increases_risk' if shap_val > 0 else 'decreases_risk'
        })

    explanations.sort(key=lambda x: x['impact'], reverse=True)
    return explanations[:top_n]


# Human-readable descriptions for each feature, so the dashboard can show
# something meaningful instead of raw variable names like "subdomain_len"
FEATURE_DESCRIPTIONS = {
    'url_length'        : 'Overall length of the URL',
    'domain_length'     : 'Length of the domain name',
    'path_length'       : 'Length of the URL path',
    'dot_count'         : 'Number of dots (.) in the URL',
    'hyphen_count'      : 'Number of hyphens (-) in the URL',
    'at_count'          : 'Number of @ symbols in the URL',
    'slash_count'       : 'Number of forward slashes in the URL',
    'quest_count'       : 'Number of question marks in the URL',
    'equal_count'       : 'Number of equals signs in the URL',
    'underscore_count'  : 'Number of underscores in the URL',
    'percent_count'     : 'Number of percent-encoded characters',
    'hash_count'        : 'Number of hash symbols in the URL',
    'amp_count'         : 'Number of ampersands in the URL',
    'digit_count'       : 'Number of digits in the URL',
    'letter_count'      : 'Number of letters in the URL',
    'digit_ratio'       : 'Proportion of the URL that is digits',
    'has_https'         : 'Whether the URL uses HTTPS',
    'has_ip'            : 'Whether the URL uses a raw IP address instead of a domain name',
    'suspicious_count'  : 'Number of suspicious keywords (login, verify, secure, etc.)',
    'brand_in_domain'   : 'Number of known brand names appearing in the domain',
    'subdomain_count'   : 'Number of subdomain parts',
    'subdomain_len'     : 'Length of the subdomain portion',
    'is_shortened'      : 'Whether a URL shortener service is used',
    'suspicious_tld'    : 'Whether the domain uses a high-risk TLD (.tk, .xyz, etc.)',
    'has_repeated'      : 'Whether the URL has repeated character patterns',
    'entropy'           : 'Randomness/unpredictability of the URL string',
    'is_typosquatting'  : 'Whether the domain resembles a misspelled brand name',
    'has_leetspeak'     : 'Whether the URL uses leetspeak substitutions (e.g. g00gle)',
}


def explain_prediction(model, features_df, top_n=5):
    """Convenience wrapper: returns explanations with human-readable text
    descriptions attached, ready to send straight to the frontend."""
    raw = get_feature_explanation(model, features_df, top_n=top_n)
    for item in raw:
        item['description'] = FEATURE_DESCRIPTIONS.get(
            item['feature'], item['feature'].replace('_', ' ').capitalize()
        )
    return raw


if __name__ == '__main__':
    # Self-test using a dummy model with the same feature structure as
    # url_analyzer.py's extract_features(), so this can be sanity-checked
    # without needing the real trained model file.
    from sklearn.ensemble import RandomForestClassifier
    import pandas as pd

    feature_names = [
        'url_length','domain_length','path_length','dot_count','hyphen_count',
        'at_count','slash_count','quest_count','equal_count','underscore_count',
        'percent_count','hash_count','amp_count','digit_count','letter_count',
        'digit_ratio','has_https','has_ip','suspicious_count','brand_in_domain',
        'subdomain_count','subdomain_len','is_shortened','suspicious_tld',
        'has_repeated','entropy','is_typosquatting','has_leetspeak'
    ]

    np.random.seed(42)
    X = pd.DataFrame(np.random.rand(200, len(feature_names)), columns=feature_names)
    y = np.random.randint(0, 2, 200)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)

    sample = X.iloc[[0]]
    result = explain_prediction(model, sample, top_n=5)
    print("Top 5 features influencing this prediction:\n")
    for r in result:
        print(f"  {r['feature']:20} impact={r['impact']:.4f}  {r['direction']:15} - {r['description']}")