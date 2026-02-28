"""EntityExtractor: GPU-accelerated NLP inference for OSINT entity extraction.

Runs on Modal A10G GPU; loads Qwen/Qwen2.5-1.5B-Instruct once per container
via @modal.enter(), then exposes three @modal.method() endpoints.
"""

import json
import re
from pathlib import Path

import modal

from app import app

# Project root – needed so gpu_image can mount the same local source tree.
_local_dir = Path(__file__).resolve().parent.parent

gpu_image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install(
        "transformers>=4.45.0",
        "torch>=2.5.0",
        "accelerate>=0.26.0",
        "sentencepiece>=0.2.0",
    )
    .env({"PYTHONPATH": "/root/osint_recon"})
    .add_local_dir(_local_dir, remote_path="/root/osint_recon")
)

_MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"
_ENTITY_KEYS = ["names", "usernames", "emails", "domains", "locations", "employers", "projects"]


@app.cls(gpu="A10G", image=gpu_image)
class EntityExtractor:
    @modal.enter()
    def load_model(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(
            _MODEL_NAME,
            trust_remote_code=True,
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            _MODEL_NAME,
            torch_dtype=torch.float16,
            trust_remote_code=True,
        ).to("cuda")
        self.model.eval()
        self.device = "cuda"

    def _run_inference(self, messages: list[dict]) -> str:
        import torch

        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = self.tokenizer([text], return_tensors="pt").to(self.device)
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=512,
                do_sample=False,
            )
        output_ids = outputs[0][len(inputs.input_ids[0]):]
        return self.tokenizer.decode(output_ids, skip_special_tokens=True)

    @modal.method()
    def extract_entities(self, text: str, source_url: str = "") -> dict:
        content = f"Source: {source_url}\n\n{text}" if source_url else text
        messages = [
            {
                "role": "system",
                "content": (
                    "Extract entities from this text. Return JSON with keys: "
                    "names, usernames, emails, domains, locations, employers, projects. "
                    "Each value is a list of strings. Return only the JSON object."
                ),
            },
            {"role": "user", "content": content},
        ]
        output = self._run_inference(messages)
        try:
            start = output.find("{")
            end = output.rfind("}") + 1
            parsed = json.loads(output[start:end]) if start >= 0 and end > start else {}
        except (json.JSONDecodeError, ValueError):
            parsed = {}
        return {
            k: parsed.get(k, []) if isinstance(parsed.get(k), list) else []
            for k in _ENTITY_KEYS
        }

    @modal.method()
    def score_identity_match(self, node_a: dict, node_b: dict) -> float:
        text_a = json.dumps(node_a, indent=2)
        text_b = json.dumps(node_b, indent=2)
        messages = [
            {
                "role": "user",
                "content": (
                    "Do these two profiles belong to the same person? "
                    "Score 0.0 to 1.0. Return only a number.\n\n"
                    f"Profile A:\n{text_a}\n\nProfile B:\n{text_b}"
                ),
            }
        ]
        output = self._run_inference(messages).strip()
        try:
            match = re.search(r"[0-9]*\.?[0-9]+", output)
            if match:
                return max(0.0, min(1.0, float(match.group())))
        except ValueError:
            pass
        return 0.0

    @modal.method()
    def get_text_embedding(self, text: str) -> list[float]:
        import torch

        inputs = self.tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        ).to(self.device)
        with torch.no_grad():
            outputs = self.model(**inputs, output_hidden_states=True)
        # Mean-pool the last hidden layer: (1, seq_len, hidden_dim) → (hidden_dim,)
        last_hidden = outputs.hidden_states[-1]
        embedding = last_hidden.mean(dim=1).squeeze(0)
        return embedding[:256].float().cpu().tolist()
