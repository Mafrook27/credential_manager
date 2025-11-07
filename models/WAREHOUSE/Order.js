const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  products: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      quantity: { type: Number, required: true },
      priceAtOrder: { type: Number, required: true } 
    }
  ],
  orderDate: { type: Date, default: Date.now },
  expectedDeliveryDate: { type: Date },
  deliveryDate: { type: Date },
  totalAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['Pending', 'Completed', 'Cancelled'], 
    default: 'Pending', 
    index: true 
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'ware_user', required: true, index: true },
}, { timestamps: true });

// Compound indexes for queries
orderSchema.index({ createdBy: 1, status: 1 });
orderSchema.index({ orderDate: -1 });

// 🔄 Pre-save hook to calculate totalAmount
orderSchema.pre('save', function (next) {
  if (this.products && this.products.length > 0) {
    this.totalAmount = this.products.reduce((sum, item) => {
      return sum + (item.priceAtOrder * item.quantity);
    }, 0);
  } else {
    this.totalAmount = 0;
  }
  next();
});

module.exports = mongoose.model('Order', orderSchema);
