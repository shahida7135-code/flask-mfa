import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

queries = [
    # SAFE examples
    ("SELECT name, email FROM users WHERE id = 10", "Safe"),
    ("INSERT INTO logs (user_id, action) VALUES (5, 'login')", "Safe"),
    ("UPDATE products SET stock = stock - 1 WHERE id = 23", "Safe"),
    ("SELECT * FROM orders WHERE user_id = 7 AND status = 'shipped'", "Safe"),
    ("DELETE FROM sessions WHERE created_at < '2024-01-01'", "Safe"),

    ("' OR '1'='1'; --", "Malicious"),
    ("SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = ''", "Malicious"),
    ("DROP TABLE users; --", "Malicious"),
    ("'; EXEC xp_cmdshell('dir'); --", "Malicious"),
    ("1; DROP TABLE accounts", "Malicious"),
    ("UNION SELECT credit_card_number FROM cards", "Malicious"),
    ("SELECT * FROM users WHERE id = 1; DELETE FROM logs;", "Malicious"),
]

X = [q for q, label in queries]
y = [label for q, label in queries]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1,2), analyzer="word")),
    ("clf", LogisticRegression(max_iter=1000, random_state=42))
])

pipeline.fit(X_train, y_train)

y_pred = pipeline.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

with open("pipeline.pkl", "wb") as f:
    pickle.dump(pipeline, f)

print("\nSaved pipeline as pipeline.pkl")
