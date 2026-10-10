const fs = require('fs');
const path = require('path');

const src = path.resolve(__dirname, '../privex-logo.svg');
const content = fs.readFileSync(src, 'utf8');

// Replace viewBox so the emblem fills a 1:1 square icon with a comfortable margin
// Original logo viewBox is "0 0 400 440", emblem top is y=40, bottom is y=312, left is x=57, right is x=343
// Centering: x min=45, x max=355 (width 310), y min=30, y max=325 (height 295) -> 320x320 centered
const emblemOnly = content
  .replace('viewBox="0 0 400 440" width="400" height="440"', 'viewBox="40 25 320 320" width="512" height="512"')
  .replace(/<!-- Wordmark -->[\s\S]*?<\/svg>/, '</svg>');

const outPath = path.resolve(__dirname, '../privex-icon.svg');
fs.writeFileSync(outPath, emblemOnly, 'utf8');
console.log('Created privex-icon.svg successfully, bytes:', emblemOnly.length);
