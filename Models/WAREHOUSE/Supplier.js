const mongoose = require('mongoose');

const supplierSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, index: true },
  email: { type: String, unique: true, sparse: true, index: true },
  phone: { type: String, unique: true, sparse: true, index: true },
  address: { type: String }, 
  category: { type: String, index: true }, // e.g. Electronics, Apparel, Groceries
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});


supplierSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});


supplierSchema.index({ category: 1, name: 1 });

module.exports = mongoose.model('Supplier', supplierSchema);
