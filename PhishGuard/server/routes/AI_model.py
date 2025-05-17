from flask import Flask, request, jsonify
import torch
from transformers import BertTokenizer, BertConfig, BertForSequenceClassification

# === Configuration ===
MODEL_DIR = r"C:\Users\abdal\OneDrive\Desktop\PhishGuardWebsite\server\routes\charbert-bert-wiki"
BEST_MODEL_PATH = f"{MODEL_DIR}/best_model.pt"
MAX_LEN = 128
LABELS = {0: "safe", 1: "malicious"}

# === Load model and tokenizer ===
tokenizer = BertTokenizer.from_pretrained(MODEL_DIR)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class CharBERTClassifier(torch.nn.Module):
    def __init__(self, model_name_or_path, num_labels, dropout_rate):
        super(CharBERTClassifier, self).__init__()
        config = BertConfig.from_pretrained(model_name_or_path)
        config.num_labels = num_labels
        config.hidden_dropout_prob = dropout_rate
        config.attention_probs_dropout_prob = dropout_rate
        self.bert = BertForSequenceClassification(config)

    def forward(self, input_ids, attention_mask, token_type_ids=None, labels=None):
        return self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            labels=labels
        )

model = CharBERTClassifier(MODEL_DIR, num_labels=2, dropout_rate=0.3)
model.bert.resize_token_embeddings(len(tokenizer))
model.load_state_dict(torch.load(BEST_MODEL_PATH, map_location=device))
model.to(device)
model.eval()

def predict_url(url):
    tokens = tokenizer(
        url,
        padding="max_length",
        truncation=True,
        max_length=MAX_LEN,
        return_tensors="pt"
    )
    input_ids = tokens["input_ids"].to(device)
    attention_mask = tokens["attention_mask"].to(device)
    token_type_ids = tokens["token_type_ids"].to(device) if "token_type_ids" in tokens else None

    with torch.no_grad():
        outputs = model(input_ids, attention_mask, token_type_ids)
        probs = torch.softmax(outputs.logits, dim=1)
        pred = torch.argmax(probs, dim=1).item()
        confidence = probs[0][pred].item()

    return {
        "prediction": LABELS[pred],
        "confidence": confidence
    }

# === Flask API ===
app = Flask(__name__)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    result = predict_url(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(port=5055, debug=False)
