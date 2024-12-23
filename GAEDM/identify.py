import torch
from torch import nn  
import torch.nn.init as init
import json
from mytrans import tokenize_function, AsmEncoder
# from model import AsmEncoder
from transformers import AutoModel, AutoTokenizer
import os
import sys
from collections import OrderedDict
target_file = r"..\CaseStudy\DRIDEX.json"
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
        init.xavier_uniform_(self.fc1.weight) 
        init.zeros_(self.fc1.bias)             
        init.xavier_uniform_(self.fc2.weight)  
        init.zeros_(self.fc2.bias)            
        init.xavier_uniform_(self.fc3.weight) 
        init.zeros_(self.fc3.bias)             
        init.xavier_uniform_(self.fc4.weight)  
        init.zeros_(self.fc4.bias)      
        init.xavier_uniform_(self.fc5.weight)  
        init.zeros_(self.fc5.bias)             
    def forward(self, input_ids):
        encoder_output = self.encoder(**input_ids).to(device) 
        logits = self.fc1(encoder_output)
        logits = self.fc2(logits)
        logits = self.fc3(logits)
        logits = self.fc4(logits)
        logits = self.fc5(logits)
        probs = self.sigmoid(logits)
        return probs
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python identify.py <encoder_path> <model_dict_path> <target_file_json>")
        exit(0)
    if os.path.exists(encoder_path):
        print("Loading encoder from", encoder_path)
    else:
        print("Model path does not exist")
        exit(0)
    encoder_path = sys.argv[1]
    # path/to/encoder
    tokenizer = AutoTokenizer.from_pretrained(encoder_path, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.unk_token
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # path/to/encoder
    encoder = AsmEncoder.from_pretrained(encoder_path, trust_remote_code=True).to(device)
    # Initialize your model
    model_path = sys.argv[2]
    target_file = sys.argv[3]
    if os.path.exists(model_path):
        print("Loading pretrained model from", model_path)
    else:
        print("Model path does not exist")
        exit(0)
    if os.path.exists(target_file):
        print("Loading target file from", target_file)
    else:
        print("Target file does not exist")
        exit(0)
    model = ModifiedModel(encoder).to(device)
    pretrained_dict = torch.load(r'.\model_dict.pth')
    new_pretrained_dict = OrderedDict()
    for k, v in pretrained_dict.items():
        new_k = k.replace('module.', '')
        new_pretrained_dict[new_k] = v

    # # Load the weights into your model
    model.load_state_dict(new_pretrained_dict)
    model.eval()
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
