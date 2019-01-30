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
wget https://github.com/azartpay/azart/releases/download/0.13.0.1/azart-0.13.0.1-linux.tgz
tar -xvf azart-0.13.0.1-linux.tgz
rm azart-0.13.0.1-linux.tgz
mv azart-0.13.0.1-linux/azartd ./azartd
mv azart-0.13.0.1-linux/azart-cli ./azart-cli
mv azart-0.13.0.1-linux/azart-tx ./azart-tx
mv azart-0.13.0.1-linux/azart-qt ./azart-qt
rm -rf azart-0.13.0.1-linux
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
echo -e "\nserver=1\nlisten=1\ndaemon=1\nmaxconnections=256\nmasternode=1\nmasternodeprivkey=$masternodekey\nrpcuser=RPCUSER\nrpcpassword=RPCPASSWORD\nrpcport=9798\nrpcallowip=127.0.0.1\naddnode=5.9.6.17:9779\naddnode=193.47.33.25:9779\naddnode=193.47.33.24:9779\naddnode=193.47.33.23:9779\naddnode=193.47.33.22:9779\naddnode=193.47.33.21:9779\naddnode=193.47.33.20:9779\naddnode=193.47.33.19:9779\naddnode=193.47.33.18:9779\naddnode=193.47.33.17:9779\naddnode=193.47.33.16:9779\naddnode=193.47.33.15:9779\naddnode=193.47.33.14:9779\naddnode=193.47.33.13:9779\naddnode=193.47.33.12:9779\naddnode=193.47.33.11:9779\naddnode=193.47.33.10:9779\naddnode=193.47.33.9:9779\naddnode=193.47.33.8:9779\naddnode=193.47.33.7:9779\naddnode=5.188.205.240:9779\naddnode=5.188.205.239:9779\n" >> "/root/.azartpay/azart.conf"
sleep 3
sudo sed -i -e "s/exit 0/sudo \-u root \/opt\/azart-core\/azartd \> \/dev\/null \&\nexit 0/g" /etc/rc.local
./azartd -daemon
echo "Masternode private key: $masternodekey"
echo "Job completed successfully"
