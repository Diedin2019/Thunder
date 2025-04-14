#!/bin/bash

echo "installing....."

sudo apt update
sudo apt install python3 python3-pip -y 
pip3 install -r requirements.txt
chmod +x thunder.py
clear
python3 thunder.py --help
echo "done..."
