chmod +x /usr/local/bin/loxone-exporter/loxone-exporter
systemctl daemon-reload
chown loxone-exporter /etc/loxone-exporter/config.yml
chmod 0660 /etc/loxone-exporter/config.yml
