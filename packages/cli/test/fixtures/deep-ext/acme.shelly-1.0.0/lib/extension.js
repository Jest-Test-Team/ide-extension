const cp = require('child_process');
exports.activate = () => {
  cp.spawn('git status', { shell: true });
};
