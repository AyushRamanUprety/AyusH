const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Employee Schema
const employeeSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  firstLogin: { type: Boolean, default: true }, // Tracks first login
});

// Hash password before saving the employee
employeeSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();  // Only hash if password is new or modified
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Validate the password
employeeSchema.methods.isValidPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

const Employee = mongoose.model('Employee', employeeSchema);


module.exports = Employee;
