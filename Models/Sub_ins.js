


const mongoose = require("mongoose");



const subInstanceSchema = new mongoose.Schema({
  name: { type: String, required: true }, //like login ,transaction
  rootInstance: { type: mongoose.Schema.Types.ObjectId, ref: "RootInstance", required: true },
  credentials: [{ type: mongoose.Schema.Types.ObjectId, ref: "Credential" }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "C_User", required: true },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });
subInstanceSchema.index({ name: 1});

subInstanceSchema.index({ rootInstance: 1 });
subInstanceSchema.index({ createdBy: 1 });
module.exports = mongoose.model("SubInstance", subInstanceSchema);

