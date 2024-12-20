<h1 align="center">GAEDM: A Novel Genetic Algorithm-Enhanced Model for Detecting API Hashing Obfuscation in Malware</h1>

<h4 align="center">
<p>
<a href=#about>About</a> |
<a href=#news>News</a> |
<a href=#quickstart>Preprocess</a> |
<a href=#quickstart>Model identification</a> |
<a href=#quickstart>Requirement</a> |
<a href=#contact>Contact</a> |
<p>
</h4>

## About

GAEDM:A Novel Genetic Algorithm-Enhanced Model for Detecting API Hashing Obfuscation in Malware

## News

- [2024/12/20] The base model of GAEDM-encoder is now available on Hugging Face Model Hub (https://huggingface.co/ChenPingAn74/GAEDM-encoder).


## introduction

GAEDM:A Novel Genetic Algorithm-Enhanced Model for Detecting API Hashing Obfuscation in Malware


## preprocess
We provide a example script to process the binary code. The script is located at `scripts/process.py`. You can use the script to process your own binaries.
```
/path/to/idat64 -c -A -S"scripts/process.py /path/to/binary_json"  /path/to/binary
```

## Model identification


```
python GAEDM/identify.py path_to_model_dict /path/to/binary_json 
```


MalwareHash.txt is the sha256 hash list of the samples refered in paper

### requirement

- Python 3.9+
- torch 1.12.0
- torchaudio 0.12.0
- torchvision 0.13.0
- transformers 4.39.2
...

you can get see all requirement in requirement.txt
## contact


- Email: blueyanglan@sina.com
