const mongoose = require('mongoose');

// Updated connection code without deprecated options
mongoose.connect('mongodb://localhost:27017/mydatabase');

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  console.log('Connected to MongoDB');
});
