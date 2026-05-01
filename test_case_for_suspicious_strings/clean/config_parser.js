const fs = require('fs');

function parseConfig(filepath) {
    const data = fs.readFileSync(filepath, 'utf8');
    return JSON.parse(data);
}

function main() {
    const config = parseConfig('./config.json');
    console.log('Configuration loaded:', config.app_name);
}

main();
