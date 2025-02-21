#!/bin/bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable nginx
sudo echo "server {

	root /var/www/html;
	index index.html index.htm index.nging-debian.html
	server_name $1.netalert.ninja

	location / {
		try_files \$uri \$uri/ =404
	}
}" > /etc/nginx/sites-available/$1
sudo ln -s /etc/nginx/sites-available/$1 /etc/nginx/sites-enabled/$1
sudo rm /etc/nginx/sites-enabled/default
sudo certbot --nginx -d $1.netalert.ninja
(sudo crontab -l 2>/dev/null; echo "0 0 * * * /usr/bin/tar -cvf "/root/backups/html-$(date +"\%m-\%d-\%Y").tar" -C /var/www/ html > /dev/null 2>&1; /usr/bin/find /root/backups/ -mtime +8 -name '*.tar' -exec /usr/bin/rm {} \;; /usr/bin/rm -rf /var/www/html/*; /usr/bin/cp -r /home/ubuntu/op/public/* /var/www/html/; /usr/bin/chown -R www-data:www-data /var/www/html/; /usr/bin/systemctl restart nginx;") | sudo crontab -
