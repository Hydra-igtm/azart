#!/bin/bash
if free | awk '/^Swap:/ {exit !$2}'; then
echo "Have swap"
else
sudo touch /var/swap.img
sudo chmod 600 /var/swap.img
sudo dd if=/dev/zero of=/var/swap.img bs=1024k count=2000
mkswap /var/swap.img
sudo swapon /var/swap.img
sudo echo "/var/swap.img none swap sw 0 0" >> /etc/fstab
fi
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get install mc htop git python-virtualenv ntpdate -y
sudo ntpdate -u pool.ntp.org
sudo mkdir /opt/azart-core
cd /opt/azart-core
wget https://github.com/azartpay/azart/releases/download/0.12.4.3/azart-0.12.4.3-linux-x64.tgz
tar -xvf azart-0.12.4.3-linux-x64.tgz
rm azart-0.12.4.3-linux-x64.tgz
mv azart-0.12.4.3-linux-x64/azartd ./azartd
mv azart-0.12.4.3-linux-x64/azart-cli ./azart-cli
mv azart-0.12.4.3-linux-x64/azart-tx ./azart-tx
mv azart-0.12.4.3-linux-x64/azart-qt ./azart-qt
rm -rf azart-0.12.4.3-linux-x64
chmod -R 755 /opt/azart-core
cd /opt
git clone https://github.com/azartpay/azart-sentinel azart-sentinel
cd azart-sentinel
virtualenv ./venv
./venv/bin/pip install -r requirements.txt
cat <(crontab -l) <(echo "* * * * * cd /opt/azart-sentinel && ./venv/bin/python bin/sentinel.py >/dev/null 2>&1") | crontab -
cd /opt/azart-core
./azartd -daemon
sleep 10
masternodekey=$(./azart-cli masternode genkey)
./azart-cli stop
sleep 3
echo -e "\nserver=1\nlisten=1\ndaemon=1\nmaxconnections=256\nmasternode=1\nmasternodeprivkey=$masternodekey\nrpcuser=RPCUSER\nrpcpassword=RPCPASSWORD\nrpcport=9798\nrpcallowip=127.0.0.1\naddnode=5.9.6.17:9799\naddnode=5.188.63.139:9799\naddnode=5.188.63.138:9799\naddnode=5.188.63.137:9799\naddnode=5.188.63.136:9799\naddnode=5.188.63.135:9799\naddnode=5.188.63.131:9799\naddnode=5.188.63.130:9799\naddnode=5.188.63.129:9799\naddnode=5.188.63.128:9799\naddnode=5.188.63.113:9799\naddnode=5.188.63.104:9799\naddnode=5.188.63.96:9799\naddnode=37.9.52.67:9799\naddnode=37.9.52.66:9799\naddnode=37.9.52.65:9799\naddnode=37.9.52.64:9799\naddnode=37.9.52.63:9799\naddnode=37.9.52.62:9799\naddnode=37.9.52.60:9799\naddnode=37.9.52.59:9799\naddnode=37.9.52.56:9799\naddnode=37.9.52.55:9799\naddnode=37.9.52.54:9799\naddnode=37.9.52.52:9799\naddnode=37.9.52.51:9799\naddnode=37.9.52.50:9799\naddnode=37.9.52.49:9799\naddnode=37.9.52.48:9799\naddnode=37.9.52.47:9799\naddnode=37.9.52.46:9799\naddnode=37.9.52.18:9799\naddnode=5.188.205.240:9799\naddnode=5.188.205.239:9799\n" >> "/root/.azartcore/azart.conf"
sleep 3
sudo sed -i -e "s/exit 0/sudo \-u root \/opt\/azart-core\/azartd \> \/dev\/null \&\nexit 0/g" /etc/rc.local
./azartd -daemon
echo "Masternode private key: $masternodekey"
echo "Job completed successfully"
