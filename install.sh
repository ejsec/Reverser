#!/bin/bash

sudo apt-get install xclip
sudo pip install pyperclip 
sudo cp reverser.py /bin/reverser
sudo chmod 777 /bin/reverser

echo -e "\e[32m [+] Now, run reverser from anywhere \e[0m"
