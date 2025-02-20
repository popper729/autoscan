#!/bin/bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable nginx
#sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/$1
sudo echo "server {

	root /var/www/html;
	index index.html index.htm index.nging-debian.html
	server_name $1.netalert.ninja

	location / {
		try_files \$uri \$uri/ =404
	}
}" > /etc/nginx/sites-available/$1
sudo ln -s /etc/nginx/sites-available/$1 /etc/nginx/sites-enabled/$1
sudo certbot --nginx -d $1.netalert.ninja
