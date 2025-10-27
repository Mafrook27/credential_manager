const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, index: true },
  sku: { type: String, unique: true, index: true },
  price: { type: Number, required: true },
  stock: { type: Number, required: true, default: 0 },
  supplier: { type: mongoose.Schema.Types.ObjectId, ref: 'Supplier', required: true, index: true },
  category: { type: String, index: true },
  createdAt: { type: Date, default: Date.now }
});

productSchema.index({ category: 1, name: 1,price: 1,name:1 }); // Compound index for category, name, and price




productSchema.pre('save', async function (next) {
  if (this.sku) return next(); 

  const categoryCode = this.category.substring(0, 4).toUpperCase();
  const productCode = this.name.substring(0, 3).toUpperCase();

  const count = await mongoose.models.Product.countDocuments({
    name: { $regex: `^${this.name}`, $options: 'i' },
    category: { $regex: `^${this.category}`, $options: 'i' }
  });

  const number = (count + 1).toString().padStart(3, '0');
  this.sku = `${categoryCode}-${productCode}-${number}`;

  next();
});

module.exports = mongoose.model('Product', productSchema);
