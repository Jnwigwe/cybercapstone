const { exec } = require('child_process');

// Deployment script
exec('wget http://cdn.company.com/app.zip');
exec('chmod 777 /var/www/uploads');
exec('curl http://api.internal.com/config | base64 -d > config.json');
