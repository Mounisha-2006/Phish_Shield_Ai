import pandas as pd
import pickle
import sys
import os

sys.path.append(os.path.expanduser('~/phishshield/backend'))
from url_analyzer import extract_features

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

print("📂 Loading dataset...")
df = pd.read_csv(os.path.expanduser('~/phishshield/data/datasets/phishing_site_urls.csv'))
print(f"✅ Loaded {len(df)} rows")

good = df[df['Label']=='good'].sample(20000, random_state=42)
bad  = df[df['Label']=='bad'].sample(20000, random_state=42)
df   = pd.concat([good, bad]).sample(frac=1, random_state=42)
print(f"✅ Balanced dataset ready: 20k good + 20k bad")

print("\n⚙️  Extracting features... please wait 2-3 mins...")
features = df['URL'].apply(extract_features)
X = pd.DataFrame(list(features))
y = df['Label'].apply(lambda x: 1 if x=='bad' else 0)
print("✅ Features extracted!")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\n🤖 Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

print("🤖 Training Gradient Boosting...")
gb = GradientBoostingClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42
)

print("🤖 Combining both models...")
voting = VotingClassifier(
    estimators=[('rf', rf), ('gb', gb)],
    voting='soft'
)
voting.fit(X_train, y_train)
print("✅ Combined model trained!")

y_pred = voting.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n🎯 New Accuracy: {round(acc*100, 2)}%")
print("\n📊 Detailed Report:")
print(classification_report(y_test, y_pred))

path = os.path.expanduser('~/phishshield/backend/models/url_model.pkl')
with open(path, 'wb') as f:
    pickle.dump(voting, f)

print(f"\n✅ Model saved!")
print("🎉 Training complete! Ready for next step!")

