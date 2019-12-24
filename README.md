# saitama


## Setup for development

1. Install nvm and node 10.0.0
```bash
# https://github.com/nvm-sh/nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.2/install.sh | bash
nvm install 10.0.0
nvm use 10.0.0
```
2. Install yarn, project requirements and start server
```bash
# https://yarnpkg.com/lang/en/docs/install/#debian-stable
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt update && sudo apt install --no-install-recommends yarn
yarn install
yarn serve
```
Now, the devlopment server will be listening at localhost:8080
3. Install python requirements and run Flask API server:
```bash
pip install -r requirements.txt
python3 server.py
```
Project requirements can be found in requirements.txt for Python and package.json for yarn.

4. (Optional) Configure vscode for Vue dev
* Install Vetur plugin
* Install ESLint plugin