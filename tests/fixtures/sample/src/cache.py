import os
# @openshell fs write /workspace/data reason="result cache"
# @openshell egress huggingface.co:443 reason="model download" allow="GET:/**"
def save(p, b):
    with open(os.path.join("/workspace/data", p), "wb") as f:
        f.write(b)
