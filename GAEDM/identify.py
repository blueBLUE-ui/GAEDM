import torch
from torch import nn
import torch.nn.init as init
import json
from mytrans import tokenize_function, AsmEncoder
from transformers import AutoTokenizer
import os
import sys
import argparse

torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class ModifiedModel(nn.Module):
    def __init__(self, encoder):
        super(ModifiedModel, self).__init__()
        self.encoder = encoder
        self.fc1 = nn.Linear(1024, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 128)
        self.fc4 = nn.Linear(128, 64)
        self.fc5 = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()
        self._initialize_weights()

    def _initialize_weights(self):
        for layer in [self.fc1, self.fc2, self.fc3, self.fc4, self.fc5]:
            init.xavier_uniform_(layer.weight)
            init.zeros_(layer.bias)

    def forward(self, input_ids):
        encoder_output = self.encoder(**input_ids).last_hidden_state[:, 0, :]  # 获取[CLS] token的输出
        logits = encoder_output
        for fc_layer in [self.fc1, self.fc2, self.fc3, self.fc4, self.fc5]:
            logits = fc_layer(logits)
        probs = self.sigmoid(logits)
        return probs


def load_model_and_tokenizer(encoder_path, model_dict_path):
    print(f"Loading encoder from {encoder_path}")
    if not os.path.exists(encoder_path):
        print(f"Error: Encoder path does not exist - {encoder_path}")
        exit(1)

    tokenizer = AutoTokenizer.from_pretrained(encoder_path, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.unk_token
    encoder = AsmEncoder.from_pretrained(encoder_path, trust_remote_code=True).to(device)
    model = ModifiedModel(encoder).to(device)

    print(f"Loading pretrained model from {model_dict_path}")
    if not os.path.exists(model_dict_path):
        print(f"Error: Model dictionary path does not exist - {model_dict_path}")
        exit(1)

    pretrained_dict = torch.load(model_dict_path, map_location=device)
    new_pretrained_dict = {k.replace('module.', ''): v for k, v in pretrained_dict.items()}
    model.load_state_dict(new_pretrained_dict)
    model.eval()
    return model, tokenizer


def process_target_file(target_file, model, tokenizer):
    print(f"Loading target file from {target_file}")
    if not os.path.exists(target_file):
        print(f"Error: Target file does not exist - {target_file}")
        exit(1)

    with open(target_file) as fp:
        data = json.load(fp)

    logits_dict = {}
    with torch.no_grad():
        for key, value in data.items():
            asm = tokenize_function(tokenizer, value)
            model_input = tokenizer.pad([asm], padding=True, pad_to_multiple_of=8, return_tensors="pt").to(device)
            logits = model(model_input)
            logits_dict[key] = logits

    sorted_keys = sorted(logits_dict.keys(), key=lambda k: logits_dict[k].max().item(), reverse=True)

    for key in sorted_keys:
        print(f"Key: {key}, Logit Max: {logits_dict[key].max().item()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process and evaluate a target file using GAEDM.")
    
    parser.add_argument(
        "encoder_path",
        type=str,
        help="Path to the encoder directory."
    )
    
    parser.add_argument(
        "model_dict_path",
        type=str,
        help="Path to the model dictionary (state dict)."
    )
    
    parser.add_argument(
        "target_file",
        type=str,
        help="Path to the target JSON file containing the data to be processed."
    )

    args = parser.parse_args()

    model, tokenizer = load_model_and_tokenizer(args.encoder_path, args.model_dict_path)
    process_target_file(args.target_file, model, tokenizer)
