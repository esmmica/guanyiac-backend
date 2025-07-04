const bcrypt = require('bcrypt');

const password = 'guanyiac'; // Change this to your desired password

bcrypt.hash(password, 10, function(err, hash) {
  if (err) throw err;
  console.log('Bcrypt hash for "' + password + '":');
  console.log(hash);
});
