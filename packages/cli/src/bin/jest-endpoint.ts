import { main } from '../endpoint';

void main(process.argv.slice(2)).then((code) => (process.exitCode = code));
